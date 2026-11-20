# Personal sensitive-data profile

This fork targets one person's Windows Claude Desktop, installed from a fixed reviewed source
commit. Its use case is a separate Google AI Studio API model in the Code tab's model menu,
alongside the unchanged native Claude subscription choices. It adds no separate chat interface.
The filtered source install omits Remote/Agent SDK/relay dependencies and the Electron distribution
packager with its unpatched `picomatch` ReDoS dependency chain. It precompiles the personal runtime;
the setup window is on demand and exits when closed. Signed and unsigned release commands refuse
to run. See [the footprint measurements and their limits](personal-footprint.md).
Use [the source installation guide](personal-windows-install.md), including its native acceptance
checks. The full commit and observed hosted test results are recorded in
[the Windows personal fork PR](https://github.com/theridgerugby/clauderipple-security/pull/2). A matching package
version alone does not identify this fork.

## Enforced boundaries

| Risk | Enforced behaviour | Regression evidence |
| --- | --- | --- |
| Accidental external disclosure | Production starts with no approved destinations. Every provider request checks a live exact HTTPS-origin allowlist. Configuration changes cannot silently grant approval. | `personal-policy.test.ts`, `admin-personal-policy.test.ts`, `security-command.test.ts` |
| Credential or prompt redirected elsewhere | Model-provider redirects are terminal; no automatic redirects, account retries or cross-provider fallback after a policy failure. Model endpoints, probes and preset-derived measurement candidates stay on their credential's base origin. Native Desktop web responses retain ordinary cache/redirect semantics without router-side redirect following. | `egress.test.ts`, `admin-egress.test.ts`, `admin-credential-origin.test.ts`, personal TLS tests |
| A request smuggled through an approved CONNECT | Locally terminated traffic requires agreement between CONNECT, SNI and inner HTTP Host. In picker mode, other explicitly approved HTTPS origins on port 443 can use opaque TLS pass-through; no blanket network allowance. Only authority-bound native Desktop WebSockets can upgrade, never model-provider inference. Absolute-form forwarding remains disabled. | `personal-policy.test.ts`, real CONNECT/TLS and Desktop compatibility tests |
| Main account exposed to an optional gateway | Rewritten provider requests use that provider's credential; native Claude traffic remains bound to `api.anthropic.com`. Built-in ChatGPT account traffic remains bound to `chatgpt.com`. | `personal-profile-smoke.test.ts`, `personal-google-desktop.test.ts` check request headers and body over real local TLS |
| An old model mapping changes a native subscription selection | Activation rejects conflicting routing and client settings. With the personal picker enabled, the runtime preserves incoming native Claude model IDs and their original credentials before old routes, classifiers, web-search or compaction overrides can redirect them. Distinct Google selections still use their own provider. | `desktop-policy.test.ts`, `desktop-activation.test.ts`, `personal-google-desktop.test.ts` |
| Prompt text or old worker settings override the selected extra | Personal Desktop routing ignores prompt markers and legacy classifier, web-reader, compaction and worker-ladder overrides. A selected extra uses its explicit primary; saved route fallbacks cannot silently choose another model. | `desktop-policy.test.ts`, personal Google local-TLS regressions |
| An ordinary setup action silently rewrites Claude defaults | Personal installation adds only owned proxy environment keys, leaving native model slots and context limits unchanged. Ordinary API-key/checklist saves never synchronize client settings, and cannot toggle picker activation. The personal UI gates unrelated configuration pages and their mutation handlers. | `desktop-install-settings.test.ts`, `admin-personal-policy.test.ts`, personal UI tests |
| Disconnecting loses unrelated settings edited while connected | Removal preserves current non-proxy settings in a clean native entry when necessary, without overwriting the previous native document. The direct-connection snapshot records the actual restored entry; concurrent edits cause a conservative refusal. | `desktop-config-preservation.test.ts`, `recovery.test.ts` |
| Hidden features keep running after the UI is simplified | Personal router startup omits unused integration construction and maintenance loops. The native setup app creates no tray, login item or recurring main-process poll/update tasks, and exits when its last window closes without stopping the router. | `desktop-runtime.test.ts`, `on-demand-lifecycle.test.ts`, native Electron lifecycle harness |
| Hidden setup endpoints alter account state or launch unrelated work | The native IPC bridge and authenticated personal admin API refuse account/OAuth, updater, Remote/phone, mod, Codex and power routes. Production CLI subscription sign-in and unrelated integration activation are refused; explicit owned cleanup stays available. | `admin-ipc.test.ts`, `admin-personal-policy.test.ts`, `security-config.test.ts`, native app harness |
| Claude cookies or custom client headers copied to a model vendor | Personal routed requests carry only a small allowlist of non-secret protocol headers. Configured provider credentials are added separately. Proxy hop-by-hop and response session-setting headers are removed. | `personal-profile-smoke.test.ts`, `proxy-headers.test.ts` |
| Provider secrets or interception CA signing keys copied off disk | Windows-owned provider/config secrets and interception CA/leaf private keys use CurrentUser DPAPI after owner/ACL/descriptor validation. No plaintext master key or migration backup. | `secret-storage.test.ts`, `config-secrets.test.ts`, `certificate-storage.test.ts`, native Windows runs |
| Extra borrowed Claude token retention | Observed client credentials remain in bounded process memory. Durable consent generations stop stale refreshes from restoring a locally revoked login. | `anthropic-observed.test.ts`, `anthropic-local-auth.test.ts`, `claude-oauth.test.ts` |
| Research reflected into diagnostic logs | Personal request history and diagnostics remain in bounded RAM, with no echo or new disk history/dump. Windows Task Scheduler and the actual Electron launcher do not redirect raw child stdout/stderr to files; inherited Electron logging and SSL-key-log sinks are removed from the child environment. | `personal-policy.test.ts`, reflected-error TLS smoke, `schtasks-definition.test.ts`, `personal-dashboard-launch.test.ts`, native scheduled-task check |
| Rapid setup/recovery overwrites an earlier backup | Each changed settings write creates an exclusive, unique backup; a failure preserves restoration evidence and leaves the client unchanged. Backups are never silently pruned. | `settings.test.ts`, `direct-ownership.test.ts` |
| Ambient Node settings weaken upstream TLS or redirect traffic | The Windows task launcher removes Node preloads, additional trust stores, insecure TLS overrides, proxy variables and debug sinks before any Node child. The router refuses unsafe direct starts; sensitive CLI commands refuse unsafe startup environments without showing their values. | `personal-windows-node-env.test.ts`, hosted Windows task run |
| Local port takeover | Native administration uses the installation's exact TLS identity and generation plus its private capability. Unknown responders and stale instances do not receive authenticated traffic. | Existing native Electron and admin transport harnesses |
| Old process mistaken for reviewed code | Startup captures a runtime source fingerprint. Install/recovery and picker activation verify the runtime before changing client proxy settings. | `install-runtime.test.ts`, `install-runtime-tls.test.ts`, recovery and picker activation tests |
| Extra models alter unrelated Desktop menus | Personal-mode additions are scoped to recognised Code surfaces. Native model entries and their context-window metadata remain untouched; invalid or unapproved extra routes are not advertised. Unknown catalogue shapes are returned unchanged. | Picker regression tests |
| A late menu reply overrides a newer selection | The memory-only selection cache scopes state by a per-process HMAC of account credentials and organization. Known Code surfaces share generation ordering; successful native changes clear extra overlays. Only the recognized `400 model_not_selectable` refusal for an approved configured extra can become a local success. | `desktop-selection.test.ts`, real TLS cases in `proxy-bootstrap.test.ts` |
| Bootstrap editing corrupts native traffic or diagnostic privacy | Encoded/decompressed sizes are bounded; unknown, malformed, integrity-protected or oversized responses preserve native bytes and headers. Successful edits replace representation metadata. Diagnostics contain fixed outcomes and counts, with bounded model labels, never cookies, raw payloads or organization paths. | `proxy-bootstrap.test.ts` |
| An encrypted configuration breaks Windows monitoring | The watchdog reads only a bounded public port through the fixed Node/private-reader helper, including DPAPI decoding. | `watchdog-port.test.ts`, native PowerShell fixture |
| A later install silently removes these protections | Bootstrap installers and executable auto-updates are disabled. Upgrades require an explicitly reviewed fixed source checkout. | `personal-bootstrap.test.ts`, update API/CLI tests |

Remote/SSH/phone activation, Grok CLI credential reuse, Google Antigravity subscription reuse,
and request-body debug dumps are disabled. The personal Google form accepts an AI Studio API key
without offering subscription sign-in. Related low-level legacy libraries
retain isolated regression tests; those tests do not create a production bypass.

The setup window does one bounded diagnostic when opened. It does not inspect an unrelated phone
host or a separate Claude Code login. Closing it cancels only its owned read-only diagnostic;
explicit repair/direct actions and the independently supervised router are not process-kill targets.
Older unmarked setup-app startup entries are not automatically removed. Review the precise old
entry before disabling it, as described in the installation guide.

Desktop picker activation also trusts the interception CA for the current Windows user and
applies an app-wide proxy setting. Both steps require explicit activation; adding a provider
does not activate interception or grant origin approvals. If the router is unavailable, Desktop
can lose connectivity. The native dashboard's **Use Claude's default connection** control and
the source CLI's `direct on` restore the owned settings; fully restart Desktop afterward.
If a legacy installation recorded a corporate proxy as the previous Desktop connection, recovery
can restore it, but resuming Ripple refuses to replace it, even with `--force`. The client settings
and restoration snapshot remain intact for review; the original connection remains available.
Other Desktop destinations still need separate exact-origin approval. TLS pass-through preserves
their encryption, but unapproved destinations remain blocked, so broad Desktop compatibility
must be checked with the actual client and connectors.

Windows DPAPI applies to project-owned provider/configuration secrets and interception
private keys. Local administration transport capabilities/keys and interoperable third-party
settings retain their separate owner-only ACL protections; they are not all DPAPI files.
Existing historical logs are not silently deleted. Start with the
fresh data directory in the guide and review old retained files separately.

## Known operational side effect: standalone Claude Code shares the proxy

The current personal source installer writes its owned `HTTPS_PROXY` and
`NODE_EXTRA_CA_CERTS` values into the user-level `~/.claude/settings.json`
(`packages/cli/src/settings.ts`). Claude Code's terminal, IDE extensions and
Desktop Code engine can all read that shared user setting. As a result, the
standalone Claude Code CLI may also use the local router and becomes dependent
on its availability while the integration is active. Native model IDs,
subscription credentials, default model slots and context limits are preserved,
but this **does not yet satisfy complete operational independence for terminal
Claude Code**. A stopped router can disrupt an otherwise ordinary subscription
session until the owned proxy settings are restored. The source guide documents
the `direct on` recovery path and the need to restart affected clients.

Picker activation also imports an interception CA into the current Windows
user's certificate trust store and changes a Desktop app-wide proxy setting.
The CA trust entry and persistent router/watchdog are additional system effects
requiring explicit consent and clean removal. The setup window may be closed;
the router and watchdog continue running. The interception CA's private key is
protected with CurrentUser DPAPI and ownership checks, but intercepting HTTPS
still creates a local trust boundary. Do not describe this as a native Claude
Desktop plugin or as zero-impact on standalone Claude Code.

A stricter goal is Desktop-only, process-scoped proxy configuration with no
changes to terminal/IDE Claude Code's user-level `settings.json`. That design
and a real owner-machine Desktop + terminal subscription coexistence test remain
acceptance gates. The existing synthetic regression tests demonstrate credential
and request routing isolation, not that broader deployment property.

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

`personal-google-desktop.test.ts` separately exercises the intended AI Studio path through the
real proxy and Google adapter with local TLS fixtures: an extra Gemini selection uses only the
Google key, native Claude keeps its subscription credentials, revoked Google approval blocks that
route without blocking native Claude, redirects do not resend the key or conversation, and stream
cancellation leaves a subsequent native turn usable. All credentials and conversation content are
synthetic; this does not contact Google or validate an actual account's model availability.
The same-conversation fixture also switches Google tool/thinking history to native Claude and
back: ordinary text/tool results survive, native signed thinking remains intact on its own path,
and Google's tool signature returns only to Google. Foreign unsigned thinking is removed before
native replay, following the existing adapter's compatibility rule.

`proxy-bootstrap.test.ts` exercises the observed menu-preference PATCH, bootstrap reload and
return-to-native flow over real local TLS, including compressed refusals, account/organization
isolation, configuration revocation, cancelled requests and out-of-order Code-surface replies.
`desktop-runtime.test.ts` executes the startup source with synthetic OS/network/service boundaries
to check that Desktop-only mode does not launch unrelated maintenance. It is not a native service
installation or real-account test.

The privacy panel also has DOM tests for explicit consent, exact revocation, safe text rendering,
failed-read/write behaviour, Google API-key-only setup and consistent picker activation consent.
Administrative policy tests use the real authenticated pinned
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
In particular, synthetic catalogue tests do not prove that the installed Desktop version uses
the same model-menu schema. An unrecognised schema remains unchanged and requires compatibility
work before an extra model can be selected. Activation refuses native-routing conflicts, and the
enabled personal picker preserves incoming native Claude model IDs even if legacy mappings
reappear. It does not undo model-default changes made by the host application itself.
Do that before opening confidential projects. A source build does not require pretending it is a
signed public installer; genuine public signing/notarization remains a separate release gate.

Destination approval permits that destination to receive the selected content. It cannot decide
whether a university, lab, collaborator or participant permits the transfer, or alter an upstream
provider's retention/training terms. Confirm those terms for the specific Google API account
and endpoint before sending unpublished material. Switching an existing conversation to Google
can send the earlier conversation context and tool results along with the new prompt.

The boundary assumes an uncompromised, current Windows account and trusted local source/runtime.
It does not defend against malicious code already executing as that user or an administrator,
prove absence of all vulnerabilities, certify Google's internal operating standards, or govern
files and logs independently retained by Claude, Codex, an editor or an upstream service.
