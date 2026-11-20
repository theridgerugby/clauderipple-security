# Experimental native Desktop integration

Status: **default-off, buffered isolation proof; not a replacement for the installed proxy.**

This proof exercises documented Claude Code mod hooks to keep native requests out of a routing
process. It is separate from the existing ClaudeRipple installer. Building it does not install or
activate anything, change Claude settings, trust a certificate, register a service, or migrate an
existing installation.

## What changes when explicitly enabled

- A separate selector appears above the Desktop Code input after passive contract verification.
  The existing account model dropdown is untouched. The selector starts on native Claude every time
  the worker starts. An ordinary successful Claude model turn supplies the verification evidence;
  no extra verification prompt, probe, model request or additional subscription usage is generated.
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
| Default | No hooks registered until explicit consent; Gemini unavailable until native traffic verifies hooks |
| Engine updates | No exact version pin. Changes reset a per-session in-memory proof; an ordinary Claude turn re-verifies it |
| Hard requirements | Documented hook/call shape, minimum feature level 2.1.323, Desktop-only scope, process.spawn and clock.after capabilities |
| Output | Whole reply buffered, then presented as a complete Messages/SSE response |
| Main inference | Selected Gemini step only; no app-wide or shared CLI proxy |
| Subagents / side calls | Native behavior remains; those calls can use Claude subscription allowance |
| Native server tools | Cannot be transferred to Google; the translator withdraws their declarations |
| Attachments | Text, inline base64 images and PDFs; unsupported blocks/URL attachments are refused |
| Host failure | Identifiable selected requests refuse locally; missing request provenance and whole-worker unload/guards remain blockers |
| Existing installation | Old proxy/CA/service settings stay until a separately verified migration |

No local test establishes zero native subscription use while Gemini is selected: subagents,
background suggestions, summaries and any host-side calls remain native. A stopped or unloaded mod
also cannot enforce a selected route outside the host hooks. Passive canary results verify only
the observed shape of an ordinary native request, not all managed guards, future hosts or complete
security. An updated engine must pass the same native canary again; earlier versions' proof expires.

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
refuse `clock.after` without exposing an acceptance-status API, so actual Windows/Desktop host
acceptance must verify that the timer is honored. The helper also has its own 10-second input and 110-second upstream
deadlines. None of these gates should be cleared with private documents or a main research API key.


## Why passive capability verification beats release pins

Claude Desktop updates its renderer, built-in Code engine and account integration on different
cadences. The stable dependencies for this extension are the **documented host contracts**:
`ui.render(AbovePrompt)`, `turn.step`, `http.fetch`, `session.version`, `process.spawn`
and `clock.after`. The last two still require real Desktop support verification. Comparing
version numbers over-fits harmless renderer fixes and misses changes to hook semantics made in
the same release series.

This implementation divides compatibility checks into four layers:

1. **Static feature floor:** the first release containing the required `AbovePrompt` support,
   currently 2.1.323. Future numeric versions can attempt the same contract; they receive no
   trust merely because their version is higher.
2. **Structural capability negotiation:** each new engine/session needs a successful native
   streaming `http.fetch` to the ordinary Anthropic Messages endpoint while a normal main
   `turn.step` using the matching Claude model is active; that step must then complete.
   The host must also expose the required process, timer, and UI capabilities.
3. **Per-selected-route proof:** a randomly scoped model marker binds the selected turn to its
   expected engine request. Gemini output appears only after its corresponding Google transport
   is observed. Unrecognized own markers are refused locally; a missing intercept refuses the
   selected completion (but cannot retroactively undo an outbound call).
4. **Independent native lane:** no shared HTTP proxy, trust root, helper process, or account
   credential access on ordinary Claude turns. The plugin can be disabled without touching the
   native account settings.

The canary costs no *additional* model requests. It requires one ordinary Claude user turn before
first-time Gemini use after starting or updating the engine. If the user's very first action is to
select Gemini, the UI explains that it is awaiting this native proof; that is a deliberate current
usability tradeoff. The separate selector does not appear as a native account model menu entry.

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

The exact-version field has been removed. A native Claude turn observed through the documented
`turn.step` and `http.fetch` hooks is an automatic, per-session capability canary. The proof
stores **only booleans and the current engine version in memory**. It copies no prompt, response,
account metadata or native credential. A new release loses its earlier proof and can regain it
after normal native usage, without editing or reinstalling this plugin. A change breaking the
required behavior keeps the Gemini selector unavailable until a compatible revision exists.

The passive canary deliberately does not originate a new Claude inference or a Google request:
the user sends a normal Claude turn, and the extension forwards the original objects unchanged.
A streamed successful `/v1/messages` request whose model matches the currently active main
step, followed by that step's completion, is required. The hook API does not expose the transport's
turn ID, so concurrent same-model side requests can still be ambiguous. An error, malformed result,
missing hook, missing `process.spawn`,
missing timer, unsupported scope or recognized incompatible engine keeps the plugin inert.

These gates support automatic patch updates. They cannot prove negative properties such as
all requests being intercepted. A host could bypass `http.fetch` only when a synthetic marker
is used, so real Windows/Desktop validation of the selected path is still essential.
The following acceptance checks must pass on the target Windows/Desktop build, using
non-sensitive fixture content and a separate test API project:

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
8. Repeat after a Desktop/engine update. Confirm its automatically expired gate is restored by
   an ordinary native Claude turn with no extra request, and that the selected Gemini request still
   uses the chosen Google route. Keep the old proxy disabled during this acceptance test; otherwise
   it can hide dependence on the architecture being replaced.

Until those checks pass, this is engineering evidence toward a lightweight design, not a promise
that a user's current or future Desktop installation will work seamlessly.

## Official interface references

- [Desktop configuration](https://code.claude.com/docs/en/desktop)
- [Mod API reference](https://code.claude.com/docs/en/plugins/mods/reference)
- [Hook events and failure behavior](https://code.claude.com/docs/en/plugins/mods/events)
- [Plugin components and sensitive configuration](https://code.claude.com/docs/en/plugins/components)
- [Google AI Studio GenerateContent](https://aistudio.google.com/api-reference/generate-content)

The documented mod surface is early access. The durable compatibility strategy combines additive
API usage, passive behavioral verification, strict selected-route attribution and a safe native
path. Routine engine patch updates no longer require a human to type a release version. Updates
that break the contract can still require a code change, and future versions cannot be guaranteed.
