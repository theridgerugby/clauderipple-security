# Security and operational acceptance gates

## Decision

**Hold production rollout.** This branch contains implemented controls and local
regression evidence. It has not passed all platform, release or operational gates.
Google's public engineering references are used as design/review guidance, not as
a certification checklist. Only the responsible release owner can accept remaining
risks after independent review and observed deployment evidence.

## Threat model and supported claims

Assets: provider API/OAuth credentials, the local admin capability, prompts and
diagnostic history, the local CA/private keys, user configuration and release artifacts.

Relevant attackers: a web page reaching loopback, an upstream provider returning
malformed or credential-reflecting data, another unprivileged local account,
untrusted dependency/build code, or an attacker controlling a mutable download.

Malware acting as the current OS user, an administrator, a compromised provider
account or a compromised signing/release authority remains outside the protections
established by these changes. This exclusion does not make these threats harmless.
Storage paths must have trusted ancestors. Product configuration can deliberately
send credentials to user-selected providers, so destination choices remain trusted
operator decisions.

## Acceptance matrix

| Gate | Current evidence | Release disposition |
| --- | --- | --- |
| Admin authentication, duplicate Host, Origin, body limits, revision concurrency | Implemented with local executable regressions | Locally verified within tests |
| Credential redaction, probe/measurement response limits | Synthetic reflected-secret and response-limit tests | Locally verified within tests |
| POSIX private files, links/owner/inode checks, atomic writes | Real temporary-file regressions | Locally verified within tests |
| Generic writes preserve shared parent permissions | Regression covers existing directory mode | Locally verified on Linux |
| Windows ACL migration, verify-only transport reads, file ownership | Shared implementation; all secret temp files get explicit owner/DACL before bytes; command-boundary mocks and native tests added; new state reads do not cache DACL decisions | Native execution pending |
| Dependency graph and known-vulnerability scan | Clean install, valid npm tree, full/prod audit | Snapshot only; scan every release |
| Electron main-frame/IPC/protocol/permission isolation | Real macOS/Windows execution exposed child-frame network attribution; administration moved to typed IPC with static-only protocol and fail-closed child-frame ownership | Revised native checks must pass; Linux runner sandbox prerequisite still blocks execution |
| Whole-repository functional regression | Hosted Ubuntu and macOS suites passed at `cf742f3`; one cloud loopback failure remains locally | Later source changes and Windows still require successful full-suite evidence |
| Claude proprietary mod engine and simultaneous provider sessions | Parser/helper tests only | Maintainer integration test required |
| Local server identity under port takeover | Dedicated pinned TLS, exact leaf/CA/IP/expiry checks, instance generation, new token namespace; real adversarial TLS regressions | Locally verified; native integration still required |
| Browser capability transport | Native-only opener and stdin helper; no capability URL, browser storage or HTTP fallback | Implemented; actual Claude engine and native launcher integration pending |
| Remote direct-phone credential exposure | Public direct WebSocket refused; HTTPS/E2EE relay required; startup atomically rotates legacy pairing tokens | Local transport and migration regressions; real upgraded phone acceptance pending |
| OS vault, certificate trust/recovery, multi-file crash recovery | File protection implemented; remaining architecture unchanged | Native design/operational review required |
| Release artifact isolation, exact-byte handoff, provenance request | Workflow and artifact regression tests | Hosted execution and provenance verification pending |
| Native package source/dependency/resource closure | Real pinned-builder resource copying, isolated CLI/Remote startup, target payload/refusal and credential-path tests | Locally verified as Node/resource checks; matching native package execution still required |
| Genuine desktop signing, notarization/timestamp, packaged fuses | Fail-closed release entry points and rejection tests; no real signer available here | Native signed build and exact-artifact install/rollback evidence required |
| Protected tags/branches and trusted publisher | Not configured or verified by this work | Maintainer configuration and evidence required |
| Secret rotation, incident handling, rollback and response ownership | Suggested controls below; no operational drill | Owner assignment and exercised runbooks required |
| Independent security review, fuzzing coverage and adversarial desktop test | Agent cross-review and deterministic regression tests only | Independent assessment required |

## Required native acceptance run

1. Use an isolated non-administrator account on each supported OS. Record the exact
   OS, architecture, Node/Electron versions and commit. No real provider credentials
   are needed for file/IPC/protocol tests.
2. Run mandatory CI checks without suppressing failures. On Linux, provide a
   supported display server and normal Chromium sandbox prerequisites. Do not use
   `--no-sandbox` or skip the real-process harness to obtain a green result.
3. On Windows, verify native ACL creation/migration, foreign-owner rejection,
   DACL cache invalidation, concurrent account writes, path quoting and installer
   rollback. Confirm preexisting user-directory ACLs are unchanged.
4. On Windows/macOS, test certificate creation/trust installation/removal and
   recovery using disposable stores or a disposable VM. Verify trust scope and
   that interruption leaves an explicit, recoverable state.
5. With explicitly authorized disposable provider accounts, check simultaneous
   Claude-subscription and Gemini-API sessions, key rotation, failures and recovery.
   Record request destinations without recording tokens or prompt bodies.
6. Follow [native-release-validation.md](native-release-validation.md) to build
   signed desktop packages, verify actual fuses and signatures, and
   install/update/rollback the packages in disposable machines. Test the exact
   artifact intended for distribution.

## Operational controls required before adoption

- Assign a security/release owner and backup; document a private reporting channel,
  severity triage, patch-response targets and dependency/runtime update ownership.
- Review minimal provider scopes and a tested procedure to revoke/rotate provider
  keys, OAuth sessions, the local admin token and local CA after suspected exposure.
- Define what is logged, permitted retention, size/disk budgets and access. Keep
  prompt-body debug logging off by default; review its content before sharing.
- Exercise failure/rollback drills for full disk, permission denial, interrupted
  key/config/update writes, lost signing authority and a compromised release.
- Protect release refs and require reviewer approval. Configure the intended npm
  trusted publisher, verify published provenance, retain exact artifacts/digests
  and validate signed desktop packages through an independent channel.
- Run periodic static analysis, property-based/fuzz tests and independent review
  against HTTP parsing, custom-protocol handling and installers. No fuzzing or
  independent penetration test is claimed by the present unit-test count.

## Public reference basis

- Google, [Building Secure and Reliable Systems, Design for Understandability](https://google.github.io/building-secure-and-reliable-systems/raw/ch06.html)
- Google, [Building Secure and Reliable Systems, Testing Code](https://google.github.io/building-secure-and-reliable-systems/raw/ch13.html)
- Google SRE, [Evolving the SRE Engagement Model and Production Readiness Reviews](https://sre.google/sre-book/evolving-sre-engagement-model/)
- Electron, [Security checklist](https://www.electronjs.org/docs/latest/tutorial/security)
- SLSA, [Build track basics](https://slsa.dev/spec/v1.2/build-track-basics)

These are public references. No access to Google's internal production acceptance
criteria, approval process or certification authority is implied.
