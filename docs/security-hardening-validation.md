# Security hardening validation

Original upstream review base: `PBJ-2/clauderipple` v0.12.36,
`e7420ab5dc14c9569fed3439bc43e68a989c7055`.
Integrated upstream revision: `7fe108c847428694e6fd05f5991c7a37c3c992fb`.
Locally tested runtime-code checkpoint: `f3057ccadf4afcccd53ea37610fc9da559420e1a`.
Validation date: 2026-11-16 (America/Toronto).
Environment: Linux cloud workspace, Node 24.22.1, npm 11.9.0.

## Decision and scope

The local port-impersonation fixes and their executable regression tests are
implemented. Native validation and genuine signed release acceptance remain
unverified. The writable fork is `theridgerugby/clauderipple-security`; hosted CI
evidence must be recorded separately from the local results below. No signed
application release or installation on the user's machine was performed. This
work does not establish a Google security certification.

See [security-acceptance.md](security-acceptance.md) for the release gates and
[native-release-validation.md](native-release-validation.md) for the exact native
handoff. A test that runs only through a command mock is not evidence of native
Windows/macOS execution.

## Executed checks

| Check | Result |
| --- | --- |
| `npm run typecheck` | Passed, including Remote web and relay configurations |
| `npm run check:mod` | Passed: 46 source files parse and 327 relative imports resolve |
| `npm run build` | Passed, including Electron TypeScript and npm distribution generation |
| `GITHUB_EVENT_NAME=pull_request npm test` | 4,007 tests: 3,976 passed, 30 skipped, 1 failed; exit code 1 |
| `npm audit --audit-level=low` | 0 reported vulnerabilities in the full dependency graph at this scan |
| `npm ls --all` | Passed; no invalid dependency tree reported |
| `node scripts/release-artifact.mjs <empty-directory>` | Passed; packed once with lifecycle scripts disabled, inspected actual archive paths/runtime files/manifest and exact bundled installer bytes |
| `git diff --check` | Passed |
| `npm run test:native --workspace @clauderipple/app` | Attempted; Electron exited before app initialization because this cloud has no working X display/D-Bus access |

The retained full-suite failure and platform skips are not counted as passes.
The dependency scan is a point-in-time known-vulnerability check, not proof that
every dependency is free of vulnerabilities. No audit threshold was lowered.

The inspected local npm archive has SHA-256
`8fac46e9a64627474bed74ee1bb563963b6e32f95f962088e1210e3274cdbd42`.
It was not published and is not a signed/native application distribution.

## Security regression evidence

- Real loopback TLS servers test a wrong CA, a replacement leaf issued by the
  same CA, wrong IP SAN, expired certificate, plaintext port impostor and redirect.
  The native clients reject these before disclosing the admin capability or body.
- Client cancellation, abort before/after body chunks, connect/idle deadlines,
  request limits and declared/chunked response limits have executable regressions.
  Cancelled or refused responses close their sockets.
- Router and Remote use separate private TLS identities, capabilities and instance
  generations. Tests reject stale generation state and prevent an old shutdown
  operation from being redirected to a replacement host.
- Stalled TLS handshakes and rejected requests with unfinished bodies cannot keep
  Remote shutdown open indefinitely. An independent real-socket repeat observed
  refusal closure within 100 ms and the bounded shutdown at approximately 251 ms.
- Legacy public Remote WebSockets receive 410. Browser tests reject direct/HTTP
  pairings without creating a socket. Existing messaging/clipboard/diff tests
  retain their business assertions while using the production E2EE handshake.
- Legacy phone-token migration is atomic and one-time. A real encrypted relay
  fixture rejects the old token and accepts the replacement. Tests cover stale
  token writes, explicit rotation compare-and-swap, exposed migrated state,
  failed persistence and failed listener binding without credential mutation.
- The retired `--new-token` flag is rejected before state or service mutations.
  Subprocess tests cover both fresh and existing state and alternate CLI entries.
- Linux tests exercise owner/mode/link/inode/size checks and atomic writes. Windows
  command-boundary tests verify safe fixed PowerShell invocation and refusal before
  writing any secret into an unprotected temporary file, including new admin
  capabilities. Additional regressions reject pathname/descriptor swaps during
  ACL operations, hard-link insertion, wrong owners and replacement during
  publication retries. Real Windows DACL assertions remain platform-specific tests.
- Renderer fixtures follow the native preload/custom-protocol contract. They
  assert no renderer bearer, same-origin requests and rejected redirects while
  preserving existing save/revision/concurrency assertions.
- Release tests reject absent/wrong signers, mixed notarization modes, unsigned
  output, altered fuse policy, unexpected artifacts and credential-bearing package
  paths. Positive signature checks in these unit tests use synthetic fixtures.
  They do not establish that a real signed/notarized artifact exists.
- Twelve resource-closure tests use the pinned builder's real file copier/config
  validation, inspect the copied dependency and source tree, and launch its CLI
  and Remote help through Node from an isolated directory with an empty home.
  They also cover missing target binaries, injected state, ABI addons, legitimate
  dependency assets, staging reservations and safe cleanup. This did not build
  or execute a native Electron package or exercise a signing service.
- The fork integration retains all 13 additional upstream commits and their
  catalogue, mapping-effort and request-purpose UI behavior. The merged provider
  probe keeps saved-secret lookup and the configured provider's catalogue selection.
- Eight new cache regressions cover bounded regular-file reads, deeply nested JSON,
  byte/value/provider limits, normalized carried-through records, long explicitly
  configured host pins, serialization failure containment, future-format retention
  and link rejection. The focused Google suites passed 73/73. A malformed local
  cache no longer rejects `fetchModels()` with an uncaught serialization error;
  unreadable/oversized files are left untouched.
- A PR-environment regression checks that production signing refusal precedes
  credential validation on both supported native hosts. The separate missing-key
  subprocess fixture clears the inherited event only within that fixture; the
  production PR-signing prohibition is unchanged.

## Retained loopback failure

`packages/remote/test/local-control.test.ts`:
`a specific interface bind adds only local control on IPv4 loopback` fails with
Node's built-in Undici `UND_ERR_SOCKET`.

A separate process importing only `node:http`, with no repository modules or
patched npm dependencies, reproduced the request-path issue: its IPv4 loopback
server returned 200, while its IPv6 loopback server bound successfully but received
zero requests before ordinary `fetch` timed out. No proxy setting, sandbox or
network restriction was bypassed. This supports an environment-path explanation;
the original test remains mandatory and must pass in the native CI environment.

## External acceptance still required

- Windows/macOS native desktop and installer tests, real OS ACL semantics,
  certificate trust/install/removal and exact-artifact update/rollback tests.
- Positive Developer ID signing/notarization or Windows Authenticode signing with
  the authorized publisher identity, plus independent verification of the actual
  distributed artifact. No real signing credential was available here.
- `claude plugin test packages/mod`, which requires the proprietary engine. Parser
  and native-helper tests do not substitute for that integration test.
- Explicitly authorized disposable provider accounts for subscription/API end-to-end
  checks. No live provider request, user token rotation, trust-store modification,
  actual update installation or release publication was performed.
- Hosted CI on the writable fork, recording the exact source revision, operating
  system, architecture and job result. The real-process Electron harness uses
  fixture windows/preloads and synthetic credentials; passing it alone does not
  establish production-application installation or signed-artifact acceptance.

Keep production rollout blocked until these gates have recorded successful
evidence against the exact reviewed source and release artifacts.
