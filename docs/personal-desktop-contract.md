# Desktop-only acceptance contract

This personal fork has one purpose: add a Google AI Studio Gemini choice to the Windows
Claude Desktop Code tab, while keeping native Claude choices and their subscription behavior.
Setup and recovery are separate from everyday use. There is no second chat app.

The owner explicitly accepts normal Claude usage from Desktop's prompt suggestions. Other native
side-call costs must remain visible during acceptance. The integration must not create an additional Claude inference for a
Google request, fall back to Claude without a selection, or redirect native auxiliary requests
to Google. Record side-call usage separately from the selected main inference.

## Observable requirements

| Action or condition | Required result | Current evidence |
| --- | --- | --- |
| Select the additional Gemini model | The main inference uses the configured Google key and model; no Anthropic inference is added | Actual local CONNECT/TLS traces with synthetic accounts |
| Select Carbon's reasoning effort | Offer its documented low/medium/high levels and send the chosen value to Google; an omitted value leaves Google's medium default | Discovery-to-picker and GenerateContent TLS regressions |
| Google refuses a request or retires the model | Show that failure; do not spend Claude quota by switching providers | Google error and no-native-connection regressions |
| Select native Claude, including a newly named `claude-*` model | Preserve the requested model, original account headers and native upstream | Native switch-back and concurrent-session traces |
| Desktop sends a native suggestion, title, compaction or subagent request | Preserve that native request, even beside a Google main request; distinguish its native usage from Gemini usage | Synthetic request-class and session-isolation traces |
| Native Claude returns an error or rate limit | Preserve full response bytes, compression and upstream retry/rate-limit headers; do not retry the Messages POST automatically | Two native hosts, four error statuses, three body encodings; separate retry-count tests |
| Close the setup window | Quit its Electron process; keep the independent router and ordinary Desktop use available | Native Windows production-entrypoint harness |
| Open setup or save a Google key | Do not sign out Claude, rewrite its model defaults, approve destinations or activate interception implicitly | IPC, backend, configuration and activation tests |
| A known Code menu gains harmless metadata | Preserve metadata and the remembered selection when its understood native preferences are unchanged | Additive-selector compatibility regressions |
| A critical selector shape becomes ambiguous or unsupported | Omit the extra on that surface, discard its stale extra selection, and retain native response semantics | Per-surface selection and bootstrap regressions |
| Revoke Google destination approval | Refuse new Google requests while leaving approved native Claude requests usable | Live-policy TLS regressions |
| Restore the default connection | Restore only owned settings, preserve intervening unrelated edits, and work without the router after a full Desktop restart | Configuration/recovery tests; owner Desktop check still required |

The network fixtures do not run Claude Desktop, contact production models, or read a billing
ledger. They measure exact requests, destinations, bodies and responses. Hosted Windows tests
use disposable local state and synthetic secrets, including real DPAPI and scheduled tasks.
They do not establish acceptance on the owner's installed Desktop build.

## Update resilience

This implementation does not patch the signed Desktop application or its signed model catalogue.
It adapts the observed Code-menu bootstrap and selection exchange in a local TLS proxy. Compatibility
is checked from the response's supported structure, rather than a hard-coded Desktop version.
Known additive fields are retained; critical ambiguities suppress the extra on the affected surface.
Native selections remain native regardless of old routing overrides.
Each retained native selector payload is limited to 64 KiB of serialized UTF-8. The cache also
keeps a cloned payload, version and bounded extra-model IDs; 64 KiB is not its total memory use.
Oversized or deeply nested optional state can disable its overlay without truncating or changing
the native response.

This protects the tested update cases. It does not establish that every future Desktop renderer,
selector protocol, bundled engine, model naming convention or Google API change is compatible.
A version that changes a required contract can need an adapter update before Gemini is selectable.
Returning native bytes for an unsupported schema is recovery behavior; it does not mean Gemini
continued to work. No version-sensitive binary patch or blanket domain approval is applied.
The native menu retains its 128-row input bound. Extras use only remaining capacity, and only
actually displayable extras can be selected or replayed. A capacity loss invalidates pending
extra selections even if capacity is restored before the old response arrives.

For the documented `gemini-4-carbon` model, the adapter maps explicit effort to
`generationConfig.thinkingConfig.thinkingLevel` on GenerateContent. Its three supported levels
and default follow Google's [thinking guide](https://aistudio.google.com/docs/thinking?generate-content=true).
Unknown future model families do not receive an invented effort menu or thinking configuration.

The [official Desktop reference](https://code.claude.com/docs/en/desktop) describes its account-based
model menu and separately updated bundled Claude Code engine. The documented
[third-party gateway mode](https://code.claude.com/docs/en/llm-gateway-connect) changes the deployment
and available features. This path does not silently convert the account to that mode.

Official [mods](https://code.claude.com/docs/en/plugins/mods/reference) expose Desktop render sites
and model-step/HTTP hooks. A separate [default-off isolation proof](native-desktop-plugin.md) now
implements that path with a small AbovePrompt selector and a one-shot Google helper. It leaves
the original menu alone and is not activated or installed by the legacy installer. Its compatibility
gate uses ordinary native traffic, current host capabilities and the minimum required feature
floor instead of a manually pinned full engine release. Engine changes trigger a new passive proof
without any extra subscription request. Complete host acceptance, true streaming, provider-state
replay and failure behavior remain gates. The official
[events guide](https://code.claude.com/docs/en/plugins/mods/events) documents that a failed hook can
fall through to the normal chain. This fork has not substituted this proof for the installed
integration, removed a managed guard, or claimed those interfaces guarantee compatibility
with all future releases.

## Availability and security boundary

Desktop's configured proxy is app-wide. While enabled, a running local router is a connection
dependency for native traffic too. The owned Windows watchdog helps recover the process; it
cannot make a stopped or stalled proxy an outage-free path. Default-connection recovery requires
restoring owned settings and fully restarting Desktop. No request is silently replayed during
recovery, and an interrupted model request is not automatically resubmitted.

Every destination requires an explicit exact-origin approval. An update, login flow, download or
connector that introduces another origin can require another approval. The integration does not
relax TLS, add all domains, alter managed policy or approve unknown services automatically to
make an update appear compatible. Approved auxiliary HTTPS services use opaque TLS pass-through.

Google sees the context sent with a selected Google request, potentially including earlier turns
and tool results from a conversation switched from Claude. Native Claude account credentials are
excluded from provider requests. The local service stores owned secrets with Windows protections;
it retains bounded diagnostics in memory and does not write request bodies to new logs. See the
[security profile](personal-security-profile.md) for precise storage and local-user assumptions.

## Minimal operating footprint

The personal dependency install excludes Remote, Agent SDK, phone/relay and distribution-packager
packages. The production CLI and router run precompiled JavaScript. The setup app has no tray,
login registration, recurring update checks or background status polling, and quits on close.
Only the local router and its owned Windows supervision remain for ordinary use.

Measured sizes and router memory have explicitly stated exclusions in
[personal-footprint.md](personal-footprint.md). The dependency inventory excludes the separately
downloaded Electron binary. The current runtime is a local service, not an in-process plugin.

## Owner acceptance before confidential work

Follow the fixed-commit [Windows source guide](personal-windows-install.md). In an empty project:

1. Record the Desktop version and the bundled engine version shown by `/status`.
2. Confirm the existing native menu choices, login, Chat, history and used connectors still work.
3. Select Gemini from the actual Code menu; check the Google model and destination in the
   memory-only request details. Native background requests can coexist and use the subscription.
4. Exercise a harmless tool call, one proposed edit, a streamed answer, cancellation and a second
   turn. Switch back to the exact native Claude model and confirm a normal answer.
5. Close setup and repeat one turn with each model. Confirm setup is not left running.
6. Exercise default-connection recovery and a full Desktop restart before relying on it.
7. After a Desktop update, repeat the short model-switch and connector check. If the extra is
   absent or a new destination is blocked, keep native use available through recovery and inspect
   the bounded compatibility status. Do not weaken permissions or replace a native model slot.

An exact candidate is ready for this check only after its full Windows CI, native security and
filtered compiled-install jobs pass. An installed-client result must be recorded separately from
synthetic test counts; a source change or green CI badge alone does not complete user acceptance.
