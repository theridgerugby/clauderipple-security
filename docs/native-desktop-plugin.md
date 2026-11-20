# Experimental native Desktop integration

Status: **default-off, buffered isolation proof; not a replacement for the installed proxy.**

This proof exercises documented Claude Code mod hooks to keep native requests out of a routing
process. It is separate from the existing ClaudeRipple installer. Building it does not install or
activate anything, change Claude settings, trust a certificate, register a service, or migrate an
existing installation.

## What changes when explicitly enabled

- A separate selector appears above the Desktop Code input. The existing account model dropdown is
  untouched. The selector starts on native Claude every time the worker starts.
- The native Claude path forwards the original hook event unchanged and does not read the Google
  key, start a helper, discover subscription credentials, or write settings.
- Only a selected main Gemini inference step gets a temporary, unique model marker. The engine's
  matching Messages request supplies the full conversation and tool schemas to one short-lived
  Node process. No native headers, cookies, subscription token or account metadata are forwarded.
- That helper translates the request, calls the fixed Google AI Studio Carbon endpoint once, and
  returns a bounded Anthropic-shaped response. Claude's harness still handles its own tool
  permissions and tool execution. The helper has no filesystem tool and executes no generated code.
- Google thought signatures remain in bounded worker memory for tool-call continuity. Unsigned
  Gemini thinking blocks are not added to the native transcript. Restarting the worker loses this
  cache; mixed-model tool-history compatibility still needs real-provider acceptance.

The API key is a sensitive plugin setting and is passed to the child only through stdin. The helper
uses fresh Google-only headers, verified TLS with Node's bundled public roots, a private direct
HTTPS agent, byte limits and a total deadline. It follows no redirects and does not retry or fall
back to Claude. Its errors are fixed strings. The caller clears common preload, proxy and log
environment options; the host process API merges rather than replaces the environment, so this is
**not a hermetic child-process boundary**. Native Windows startup validation remains mandatory.

## Deliberate limits

| Item | Current proof |
| --- | --- |
| Installation | Separate build only; no automatic activation or migration |
| Selector | Above the Code input, separate from the original account dropdown |
| Default | No hooks registered until explicit consent; no engine version accepted by default |
| Engine updates | Exact owner-validated version required; revalidate after changes |
| Output | Whole reply buffered, then presented as a complete Messages/SSE response |
| Main inference | Selected Gemini step only; no app-wide or shared CLI proxy |
| Subagents / side calls | Native behavior remains; those calls can use Claude subscription allowance |
| Native server tools | Cannot be transferred to Google; the translator withdraws their declarations |
| Attachments | Text, inline base64 images and PDFs; unsupported blocks/URL attachments are refused |
| Host failure | Identifiable selected requests refuse locally; missing request provenance and whole-worker unload/guards remain blockers |
| Existing installation | Old proxy/CA/service settings stay until a separately verified migration |

No local test establishes zero native subscription use while Gemini is selected: subagents,
background suggestions, summaries and any host-side calls remain native. A stopped or unloaded mod
also cannot enforce a selected route outside the host hooks. The proof's owner-version field is an
acceptance attestation, not a check that detects all managed guards or proves safety.

The HTTP hook exposes no request-level turn/agent identifier. A malformed, byte-encoded or oversized
body cannot be reliably attributed to a selected Gemini step rather than an unrelated native side
call. The proof leaves those unclassifiable requests alone to preserve native behavior. A later
missing-interception check prevents presenting an unobserved completion as Gemini, but it cannot
undo an outbound call. This is a concrete unresolved fail-closed gap, not a completed guarantee.
Recognizable expired or forged model markers in the proof's own namespace are refused locally.

The one-shot helper uses the documented `process.spawn` stream. An aborted dispatch, module unload,
output limit or 120-second deadline requests child termination; late output is discarded. Its
stdout, stderr and output-chunk counts are bounded, and it never prints raw child diagnostics.
Mock tests verify the close request and timer cleanup, including a child that never acknowledges
closure. Actual process termination still needs verification on Windows/Desktop. The host may
refuse `clock.after` without exposing an acceptance-status API, so the exact-build test must verify
that this timer is honored. The helper also has its own 10-second input and 110-second upstream
deadlines. None of these gates should be cleared with private documents or a main research API key.

## Build and validate without activation

Use the repository's existing Node 24 development installation:

```sh
npm run check:native-plugin
npm run test:native-plugin
npm run build:native-plugin
```

The last command prints a new `native-plugin-build-*/gemini-native-experimental` directory. It
contains the hook source, the compiled helper's exact import closure, license, documentation and
SHA-256 inventory. It includes no npm runtime packages, SDK, router, Electron binary, listening
service, CA or account files. Node 24 itself is required separately and is not counted as package
bytes. An inventory hash detects file changes when compared to a trusted build; it is not a signing
certificate or a provenance attestation.

Run the host's `claude plugin validate <built-directory>` on a test machine before loading the
plugin. Type-check against that exact engine's generated `claude-code` declarations. The source has
also been checked against the retrieved official declarations used for this review; that static
check does not establish installed Desktop behavior. This source-only CI intentionally does not
download a proprietary engine, use real account credentials, or enable any plugin.

Do not fill `validated_engine_version` merely to dismiss a warning. The following checks must pass
on the target Windows/Desktop build first, using non-sensitive fixture content and a separate test
API project:

1. With the plugin absent, off, missing its key, blocked, or crashed, native Chat and Code, login,
   attachments, native tool approval and standalone Claude Code work normally.
2. A native turn with the plugin enabled has no helper process, Google request, extra auth/profile
   lookup or settings write. Record the real transport path, not only the displayed model name.
3. A selected Gemini turn reaches only the intended Google endpoint, receives the full needed tool
   schemas, respects native approvals, and never silently completes through a native fallback.
4. Validate cancellation, rejected/expired keys, limits, malformed responses, helper timeout, worker
   termination and hook guards. Observe the child actually exiting after cancellation and confirm
   that the host honors the deadline timer. Confirm what happens when the whole mod disappears.
5. Switch explicitly back to Claude after ordinary text, attachments and complete tool rounds.
   A native request must accept the resulting history without foreign thinking signatures.
6. Verify mixed-case inherited environment variables, executable provenance and stdin/log handling
   using the real Windows host process API. Never put the API key in a command line or logs.
7. Observe the native subscription and Google usage separately, including subagent/side-call costs.
8. Repeat after a Desktop/engine update. Keep the old proxy disabled during this acceptance test;
   otherwise it can hide dependence on the architecture being replaced.

Until those checks pass, this is engineering evidence toward a lightweight design, not a promise
that a user's current or future Desktop installation will work seamlessly.

## Official interface references

- [Desktop configuration](https://code.claude.com/docs/en/desktop)
- [Mod API reference](https://code.claude.com/docs/en/plugins/mods/reference)
- [Hook events and failure behavior](https://code.claude.com/docs/en/plugins/mods/events)
- [Plugin components and sensitive configuration](https://code.claude.com/docs/en/plugins/components)
- [Google AI Studio GenerateContent](https://aistudio.google.com/api-reference/generate-content)

The documented mod surface is early access. The durable compatibility strategy is to leave native
behavior intact and disable an unvalidated Gemini path, with an explicit way back to Claude. An
unconditional guarantee about all future Desktop releases would exceed the evidence.
