# Personal sensitive-data profile

This fork targets one person's Windows computer, installed from a fixed reviewed source commit.
Use [the source installation guide](personal-windows-install.md), including its native acceptance
checks. The full commit and observed hosted test results are recorded in
[the Windows personal fork PR](https://github.com/theridgerugby/clauderipple-security/pull/2). A matching package
version alone does not identify this fork.

## Enforced boundaries

| Risk | Enforced behaviour | Regression evidence |
| --- | --- | --- |
| Accidental external disclosure | Production starts with no approved destinations. Every provider request checks a live exact HTTPS-origin allowlist. Configuration changes cannot silently grant approval. | `personal-policy.test.ts`, `admin-personal-policy.test.ts`, `security-command.test.ts` |
| Credential or prompt redirected elsewhere | All 300–399 responses are terminal; no automatic redirects, account retries or cross-provider fallback after a policy failure. Model endpoints, probes and preset-derived measurement candidates stay on their credential's base origin. | `egress.test.ts`, `admin-egress.test.ts`, `admin-credential-origin.test.ts`, `personal-profile-smoke.test.ts` |
| A request smuggled through an approved CONNECT | Only known locally terminated hosts on port 443; CONNECT, SNI and inner HTTP Host must agree. Opaque tunnels, absolute-form forwarding and upgrades are disabled. | `personal-policy.test.ts`, real CONNECT/TLS smoke |
| Main account exposed to an optional gateway | Rewritten provider requests use that provider's credential; native Claude traffic remains bound to `api.anthropic.com`. Built-in ChatGPT account traffic remains bound to `chatgpt.com`. | Real TLS native/school fixture checks request headers and body |
| Claude cookies or custom client headers copied to a model vendor | Personal routed requests carry only a small allowlist of non-secret protocol headers. Configured provider credentials are added separately. Proxy hop-by-hop and response session-setting headers are removed. | `personal-profile-smoke.test.ts`, `proxy-headers.test.ts` |
| Provider secrets or interception CA signing keys copied off disk | Windows-owned provider/config secrets and interception CA/leaf private keys use CurrentUser DPAPI after owner/ACL/descriptor validation. No plaintext master key or migration backup. | `secret-storage.test.ts`, `config-secrets.test.ts`, `certificate-storage.test.ts`, native Windows runs |
| Extra borrowed Claude token retention | Observed client credentials remain in bounded process memory. Durable consent generations stop stale refreshes from restoring a locally revoked login. | `anthropic-observed.test.ts`, `anthropic-local-auth.test.ts`, `claude-oauth.test.ts` |
| Research reflected into diagnostic logs | Personal request history and diagnostics remain in bounded RAM, with no echo or new disk history/dump. | `personal-policy.test.ts`, reflected-error TLS smoke |
| Local port takeover | Native administration uses the installation's exact TLS identity and generation plus its private capability. Unknown responders and stale instances do not receive authenticated traffic. | Existing native Electron and admin transport harnesses |
| Old process mistaken for reviewed code | Startup captures a runtime source fingerprint. Install/recovery verify it, installation identity and configured listeners before changing client proxy settings. | `install-runtime.test.ts`, `install-runtime-tls.test.ts`, recovery tests |
| An encrypted configuration breaks Windows monitoring | The watchdog reads only a bounded public port through the fixed Node/private-reader helper, including DPAPI decoding. | `watchdog-port.test.ts`, native PowerShell fixture |
| A later install silently removes these protections | Bootstrap installers and executable auto-updates are disabled. Upgrades require an explicitly reviewed fixed source checkout. | `personal-bootstrap.test.ts`, update API/CLI tests |

Remote/SSH/phone activation, Grok CLI credential reuse, Google Antigravity subscription reuse,
and request-body debug dumps are disabled. Ordinary Google API keys and explicitly configured
OpenAI-compatible university endpoints remain supported. Related low-level legacy libraries
retain isolated regression tests; those tests do not create a production bypass.

Windows DPAPI applies to project-owned provider/configuration secrets and interception
private keys. Local administration transport capabilities/keys and interoperable third-party
settings retain their separate owner-only ACL protections; they are not all DPAPI files.
Existing historical logs are not silently deleted. Start with the
fresh data directory in the guide and review old retained files separately.

## Normal-use verification

`personal-profile-smoke.test.ts` runs the real proxy and provider adapter against locally trusted
HTTPS fixtures with TLS verification enabled. Synthetic native-account credentials, a different
school key and synthetic unpublished text test:

1. Complete native JSON and native SSE replies.
2. A complete OpenAI-compatible school reply with only the school credential.
3. Immediate refusal after origin revocation and successful recovery after explicit approval.
4. Redirect refusal even when the second origin is independently approved, with zero connections
   and zero requests to that destination and no native-provider fallback.
5. CONNECT/Host mismatch refusal before outbound connections, including bodyless requests with
   custom credential headers.
6. Reflected private content remaining off disk.
7. Untrusted-CA rejection before any research request.
8. Anthropic-compatible routing strips Claude cookies, proxy credentials and arbitrary client keys while preserving explicitly configured provider headers.
9. Compatible responses cannot set Claude-origin cookies; Connection-nominated headers are removed in both directions.

The privacy panel also has DOM tests for explicit consent, exact revocation, safe text rendering
and failed-read/write behaviour. Administrative policy tests use the real authenticated pinned
TLS listener and live configuration reload. These checks use no real account, API key, research
document, trust-store modification or external inference call.

Hosted Windows also runs `windows-personal-install.test.ts`, exercising a uniquely named
Task Scheduler entry, real background router startup, DPAPI-protected configuration,
pinned identity, refusal before writing disposable client settings, restart and
owned-task cleanup. It uses synthetic credentials and leaves Windows trust stores untouched.

## Acceptance and limits

Use the exact commit whose Windows full suite, native Electron boundaries and personal gates
have completed successfully. Skipped Windows-only tests on Linux are not Windows evidence.
The unrelated Linux sandbox-image prerequisite is not waived or bypassed by this profile.

The user's actual Windows service installation, Claude client build, real account permissions and
chosen model availability still require the short disposable-project acceptance in the guide.
Do that before opening confidential projects. A source build does not require pretending it is a
signed public installer; genuine public signing/notarization remains a separate release gate.

Destination approval permits that destination to receive the selected content. It cannot decide
whether a university, lab, collaborator or participant permits the transfer, or alter an upstream
provider's retention/training terms. Confirm those terms for the specific account and endpoint
before sending unpublished material. A university gateway and a direct personal/free model API
are distinct destinations.

The boundary assumes an uncompromised, current Windows account and trusted local source/runtime.
It does not defend against malicious code already executing as that user or an administrator,
prove absence of all vulnerabilities, certify Google's internal operating standards, or govern
files and logs independently retained by Claude, Codex, an editor or an upstream service.
