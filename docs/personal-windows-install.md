# Windows Claude Desktop with a Google AI Studio API key

This path uses a fixed source checkout of
[`theridgerugby/clauderipple-security`](https://github.com/theridgerugby/clauderipple-security).
It applies to the personal-mode revision that contains this guide and the `security approve-origin`
command. It does not install the package named `clauderipple` from npm. The upstream README's
one-line installers, including a copied `install.ps1`, can select that upstream package instead.

Use the **full 40-character commit SHA associated with the completed review and test results**.
A version such as `0.12.36` is insufficient: the fork and upstream may have the same version.
Do not substitute a moving branch, `HEAD`, or an earlier SHA that predates personal mode.
This is a source-based personal trial, not a signed-installer release or a security certification.
The personal fork excludes the Electron distribution packager and disables all `dist` / `release`
scripts. Its build-only dependency chain contained an unpatched high-severity `picomatch`
advisory, and native distribution is outside this Windows source-install path. Keep the
read-only `npm audit --audit-level=low` gate enabled before installing a reviewed commit.

The intended everyday interface is **Claude Desktop's Code tab**. Add a distinct Google model
entry to that menu and keep the existing Claude choices on their normal subscription path.
The local dashboard is for setup, privacy approvals and recovery; it is not a second chat app.
It opens on demand and exits when its last window closes. The independent local router and
its Windows watchdog remain available for Desktop; closing setup does not disconnect either model.
This guide does not require terminal Claude Code use, a university gateway, or replacing native
Opus/Sonnet/Haiku choices. First installation still uses PowerShell to run the reviewed source.

**Current graphical-picker gate:** the adapter covers the observed
`model_selector_config` Code surfaces. The upstream author's architecture notes record a live
Windows Desktop 4.4212 test on November 3, 2026, with native entries followed by eight injected
entries. This is newer evidence than the October 25 compatibility backlog; neither is a live
test of the owner's installed build. The [official Desktop reference](https://code.claude.com/docs/en/desktop)
says the terminal `modelPicker` setting does not add models to the account-based Desktop menu.
The documented third-party `inferenceModels` path changes the deployment/profile; it has not
been established as an additive extension that preserves this subscription setup. Do not treat
a working backend or successful activation as completion of the requested graphical picker.
First identify the installed Desktop build and verify its menu state with synthetic content.
Do not export authentication cookies, whole bootstrap payloads, conversation text or API keys
to diagnose this. Anthropic's signed model catalogue is metadata, not the offered-model list;
its signature and the official application remain unchanged.

## 1. Before starting

- Use your ordinary Windows account, not an elevated administrator shell. Have Git and a supported
  Node.js 24 installation available. Do not disable certificate validation, endpoint protection,
  Electron's sandbox, or Windows execution-policy protections to get past an error.
- Use a fresh PowerShell window without Node preload flags, custom TLS trust stores or ambient
  HTTP proxy settings. Node can disable HTTPS certificate validation with
  `NODE_TLS_REJECT_UNAUTHORIZED=0`; `NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`, and
  `NODE_USE_ENV_PROXY` can change upstream trust or routing. The personal CLI refuses unsafe
  startup settings before installing or authenticating. Its Windows scheduled-task launcher
  clears inherited Node/proxy/debug settings before starting the background router; the router
  independently refuses unsafe direct starts. Inspect unexpected variables and resolve their
  source before continuing. Do not solve a refusal by disabling a security check.
- Save current work and fully quit Claude Desktop and existing Claude Code sessions.
- If an older ClaudeRipple is installed, use its **known, original installation's own controls** to
  switch Claude to direct connection and uninstall its owned service first. Keep its data for now.
  A stopped but still registered task owned by another home is not a free slot for this installation.
  Do not kill an unknown process, delete an unidentified scheduled task, or add `--force` to resolve
  an ownership error.
- Earlier setup apps could have registered themselves as Windows startup apps. This version
  creates no setup-app startup entry and does not delete old entries automatically. Review the
  exact executable and arguments in Windows Startup Apps or the old installation's controls;
  disable only the confirmed old setup entry. Keep the independently owned router task enabled.
  An old unmarked entry can otherwise open the new setup window at login; closing it exits.
- Do this before running the new CLI against an old data home. On Windows, reading an existing
  configuration can migrate its secret storage to DPAPI, which older builds cannot read.
- The instructions below use a fresh data home and source directory under your account. They do
  not copy old API keys or proxy configuration. Keep both directories in a trusted, local,
  owner-controlled location, outside shared or synchronised project folders.

Run the following in an ordinary PowerShell window. Set the reviewed SHA deliberately:

```powershell
$ErrorActionPreference = 'Stop'
$ReviewedCommit = '<paste the full reviewed 40-character commit SHA>'
if ($ReviewedCommit -notmatch '^[0-9a-f]{40}$') { throw 'A reviewed full commit SHA is required.' }

$PersonalSource = Join-Path $env:LOCALAPPDATA 'ClaudeRipplePersonalSource'
$PersonalData = Join-Path $env:LOCALAPPDATA 'ClaudeRipplePersonalData'
if ((Test-Path $PersonalSource) -or (Test-Path $PersonalData)) {
    throw 'One of the trial directories already exists. Inspect it before choosing a fresh directory.'
}

# Inspect the startup environment before running Node, without printing variable contents.
$UnsafeSetVariables = @('NODE_OPTIONS','NODE_EXTRA_CA_CERTS','SSL_CERT_FILE','SSL_CERT_DIR',
  'OPENSSL_CONF','SSLKEYLOGFILE','NODE_DEBUG','NODE_V8_COVERAGE',
  'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')
foreach ($name in $UnsafeSetVariables) {
  if ([Environment]::GetEnvironmentVariable($name, 'Process')) {
    throw "Unsafe inherited Node/proxy setting: $name. Inspect and use a clean PowerShell environment."
  }
}
if ($env:NODE_TLS_REJECT_UNAUTHORIZED -eq '0' -or
    $env:NODE_USE_SYSTEM_CA -eq '1' -or $env:NODE_USE_ENV_PROXY -eq '1') {
  throw 'Node TLS verification, CA selection or environment proxy settings are unsafe for this trial.'
}

$NodeMajor = & node -p "process.versions.node.split('.')[0]"
if ($LASTEXITCODE -ne 0 -or $NodeMajor -ne '24') { throw 'Use the supported Node.js 24 runtime.' }

git clone --no-checkout https://github.com/theridgerugby/clauderipple-security.git $PersonalSource
if ($LASTEXITCODE -ne 0) { throw 'Clone failed.' }
Set-Location $PersonalSource
git fetch origin $ReviewedCommit
if ($LASTEXITCODE -ne 0) { throw 'Could not fetch the reviewed commit.' }
git checkout --detach $ReviewedCommit
if ($LASTEXITCODE -ne 0) { throw 'Checkout failed.' }
$CheckedOut = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $CheckedOut -ne $ReviewedCommit) { throw 'Source identity mismatch.' }

$env:CLAUDERIPPLE_HOME = $PersonalData
```

Keep this shell open. In a later shell, set the same `CLAUDERIPPLE_HOME` and return to the same
source directory before using the commands below. Always call the checkout's explicit CLI path;
a globally installed `clauderipple` command may belong to a different build.

## 2. Build the small precompiled personal runtime without installing a service yet

```powershell
npm.cmd ci --workspace @clauderipple/app --include-workspace-root --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency installation failed.' }

node scripts/check-personal-install.mjs
if ($LASTEXITCODE -ne 0) { throw 'Personal dependency inventory failed verification.' }

npm.cmd audit --audit-level=low
if ($LASTEXITCODE -ne 0) { throw 'Dependency audit failed. Review the advisory before installing.' }

# Explicitly download the locked Electron runtime. This is the reviewed package's downloader,
# not an upstream ClaudeRipple installer. A skipped or blocked download must be resolved first.
node node_modules/electron/install.js
if ($LASTEXITCODE -ne 0) { throw 'Electron runtime download failed.' }

npm.cmd run build:personal
if ($LASTEXITCODE -ne 0) { throw 'Build failed. Do not install a partially built checkout.' }

node dist/cli/src/index.js --help
if ($LASTEXITCODE -ne 0) { throw 'The checkout CLI could not run.' }

npm.cmd run smoke:personal
if ($LASTEXITCODE -ne 0) { throw 'Compiled runtime smoke checks failed. Do not install this checkout.' }
```

The dependency install and explicit Electron download require internet access. A
corporate registry, custom Electron mirror, or download-blocking policy needs its own review.
Do not respond to download or TLS errors by turning verification off. Keep the checkout in place:
the scheduled task and dashboard launcher will reference these files.

Use the workspace filter exactly as shown. The unfiltered developer install also brings in
Remote-host and Cloudflare tooling that this Desktop-only install never uses. The inventory
check refuses those extra packages, missing dependencies and lock-version mismatches. The
personal build compiles only the router/recovery dependency closure and the native setup app;
it omits the Remote host/web, full mod and installer bundles. It verifies staged output before
replacing a recognized generated `dist` directory. Do not rebuild or replace a live installation:
restore direct connection and stop its owned service first, or use a fresh reviewed checkout.
The locked Electron runtime still occupies disk space, but is not kept running after setup closes.
See [the measured footprint](personal-footprint.md) for the precise scope of size/memory numbers.

## 3. Approve the destinations you actually intend to use

Personal mode starts with an empty destination allowlist. Approval means that prompts, tool output,
code and the relevant credential **may be sent to that exact HTTPS origin** when you use it.
Approval does not grant an API subscription or waive the provider's data-use terms.

To retain normal Claude/Opus traffic and allow the installer's credential-free connection probe:

```powershell
node dist/cli/src/index.js security approve-origin https://api.anthropic.com --acknowledge-data-sharing
if ($LASTEXITCODE -ne 0) { throw 'Native Claude destination approval failed.' }
```

The Desktop picker also needs its native application origin. Approve it explicitly before
turning on picker mode:

```powershell
node dist/cli/src/index.js security approve-origin https://claude.ai --acknowledge-data-sharing
if ($LASTEXITCODE -ne 0) { throw 'Claude Desktop destination approval failed.' }
```

For your Google AI Studio API key, approve Google's API origin separately:

```powershell
node dist/cli/src/index.js security approve-origin https://generativelanguage.googleapis.com --acknowledge-data-sharing
if ($LASTEXITCODE -ne 0) { throw 'Google API destination approval failed.' }
```

No wildcard, HTTP URL, user-info component, query or API path belongs in this approval command.
Only approve origins whose owner and purpose you have checked. Additional OAuth destinations,
asset downloads or connectors may need their own exact-origin approval. The proxy does not
silently approve them. In picker mode, other approved HTTPS origins on port 443 use encrypted
pass-through, with TLS checked end-to-end by Desktop. The proxy does not decrypt those connections.
Do not broadly approve domains in response to a failed login.

## 4. Install and open the native dashboard

```powershell
node dist/cli/src/index.js install
if ($LASTEXITCODE -ne 0) { throw 'Installation is incomplete. Read the refusal before retrying.' }

node dist/cli/src/index.js doctor --json
if ($LASTEXITCODE -ne 0) { throw 'The diagnostic command failed.' }

node dist/cli/src/index.js ui
if ($LASTEXITCODE -ne 0) { throw 'The native dashboard could not open.' }
```

Check the doctor's JSON, not only its exit code: `router.responding` and `router.runtimeVerified`
must both be `true`. A diagnostic command can exit successfully while reporting an unhealthy
installation. Install separately verifies the live process's installation ID, executable/script
paths, startup source fingerprint, configured listener and upstream, then probes the data path
and verifies the same instance again **before changing Claude's proxy settings**. A plain HTTP
responder, missing proof, same-version different source, failed restart, or failed probe stops
that settings change. Private setup files or a service registration may still have been created.

If install cannot identify an older process, exit it using that installation's own controls and
retry. Do not bypass the identity check. A later settings-write failure is reported separately;
inspect the retained settings backup rather than assuming all earlier setup was rolled back.

Before picker activation, the setup changes are:

| Area | Change |
| --- | --- |
| Personal data directory | Owner-private local keys/state; DPAPI-protected provider-credential/config storage, bound to this Windows user |
| Diagnostics | Bounded RAM history while the router runs; headless task and setup subprocesses do not write raw stdout/stderr to durable log files |
| Task Scheduler | An owned `ClaudeRippleRouter` logon task, using the interactive user with limited privileges |
| Claude Code settings | Owned `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` entries, with a backup and ownership record; native model defaults and global context limits are left unchanged |
| Local listeners | Loopback proxy, authenticated certificate-pinned admin TLS, and a separate liveness-only HTTP listener for the watchdog; no privileged browser dashboard |
| App launcher | Per-user shortcuts that open this build's on-demand native setup window; no new setup-app login item or tray residency |

The task uses a child PowerShell invocation with a process-specific execution-policy argument;
it does not require changing the system's permanent execution policy. The dedicated admin CA is
not imported into the Windows trust store. The separate proxy CA is trusted in the **current
user's** root store only when you explicitly enable the Desktop picker in the next step.

## 5. Add Google to the Desktop Code menu

1. In the native dashboard, open **Providers**, add **Google**, and enter your Google AI Studio
   API key. Personal mode offers API-key access only. Use a separate, limited key where available;
   enter it in this native form, never a command, issue, screenshot or chat message.
2. Run the provider's connection/model check. Select the exact Gemini model returned for your
   account. Choose Carbon only if its actual model ID is available to this API key. Account
   billing, quota and model access belong to Google and are separate from Claude's subscription.
3. Select **Show in the Claude app picker** and save. This creates an additional model entry.
   Leave all original Claude model mappings unchanged. Do not rename a Claude slot to hide a
   Google route, configure cross-provider fallbacks, or replace the native subscription login.
4. Enable **Model picker** under **Desktop**, or accept the activation offer after saving.
   Read its explanation and the Windows certificate dialog. Activation requires an approved
   native API/Desktop destination and a verified running router; a refusal must be resolved
   before retrying. Saving a provider alone does not grant destination approval.
5. Fully quit Claude Desktop, including its tray process, and reopen it. Open a new **Code**
   session and inspect the model menu. The expected result is unchanged native Claude entries
   plus the selected Gemini entry. Chat and Cowork menus are not targets for added models.
6. Close the setup window. It should disappear from running apps while the router task remains
   running. Send one harmless native turn, one Google turn, then select native Claude again.
   Reopen setup only to change a key/model, review an approval, inspect status or recover.

The picker adapter edits only recognised Code surfaces in the native model catalogue. If a
Desktop update changes that catalogue to an unknown format, it leaves the response unchanged.
A successful activation therefore does not by itself prove the current dropdown shows Gemini.
If the additional entry is absent, stop the acceptance test and keep native Claude available
through the default-connection recovery path; do not replace a native Claude entry to hide the
compatibility failure. Activation refuses conflicting native model mappings, automatic switching
and client settings before changing Desktop. While the personal picker is enabled, the runtime
keeps incoming native Claude model IDs on the original Anthropic path even if an old mapping
reappears. This does not undo model-default changes made by Desktop itself or make an unknown
catalogue schema compatible.

The selection adapter also handles the observed Code-menu preference update. It recognizes only
the native `model_not_selectable` refusal for an explicitly configured and approved extra model,
after this signed-in account's native menu state has been observed. Other errors, including login,
permission and quota failures, are returned unchanged. Native Claude selection requests and replies
retain their original bytes. Quick successive changes share one ordering across the two known
Code surfaces so an older Gemini request cannot undo a later Claude choice.

Extra-model selection is remembered only in bounded process memory, scoped to the signed-in
account and organization. A router restart, configuration change, account-cookie change or 30
minutes of inactivity can clear it; select the extra again if Desktop returns to its native
default. Effort-only and fast-mode preference writes pass through to Claude unchanged and clear
the local extra overlay on native success. Current-build effort controls need their own acceptance
check. The adapter does not store session cookies or fabricate a Google account entitlement.

For source-command activation, use the same reviewed checkout and data home:

```powershell
node dist/cli/src/index.js picker on
if ($LASTEXITCODE -ne 0) { throw 'Desktop picker activation failed. Read the refusal before retrying.' }
```

Picker mode routes Desktop's app traffic through the local proxy and introduces a running-router
dependency. It does not change your subscription or make Google API usage part of that subscription.
Only approved destinations can connect. A new Desktop build, sign-in flow, download or remote
connector may require an additional explicit approval. If ordinary functionality is affected,
use **Use Claude's default connection** in the dashboard and fully restart Desktop, then inspect
the **Recently blocked destinations** note under **Desktop**. It lists bounded, recent HTTPS
origins without request paths or credentials. Check each service's owner and purpose before
using **Review permission** to open that exact destination's consent form. An approval covers
both provider egress and opaque Desktop connections to that origin; it is not an assets-only
permission. No captured request is replayed by the approval action. Do not work around a failure by
disabling TLS checks or opening all outbound destinations.

## 6. Run the native acceptance test before confidential work

Use an empty, disposable project with public or synthetic text. The current Desktop UI and your
actual account have not been validated merely because the local test suite passes.

1. Confirm Desktop remains signed in and its ordinary Chat, history and a harmless attachment
   operation work. Check the local connectors you use, including their normal approval controls.
2. In a new Code session select native Opus or Sonnet and request a short answer. Confirm the
   native Anthropic path remains selected and no Google request was made for that turn.
3. In another new Code session select the new Gemini entry and request a short answer. Check the
   dashboard's in-memory request details for the expected Google provider and actual model ID.
4. Test a harmless file read, proposed edit, cancellation and a second turn. Then switch back to
   a native Claude choice and verify it still answers normally. Test a longer disposable session
   before expecting cross-model context/tool compatibility in important work.
5. Revoke the Google origin and confirm a new Google request is refused. Reapprove it only if you
   want to resume. Keep unpublished research out of this test. Switching a conversation to Google
   may send its existing context and tool results to Google too.
6. Use the default-connection recovery control, restart Desktop, and confirm ordinary Claude
   works without the router. Restore Ripple only after its runtime check succeeds and restart
   Desktop again. This exercises the recovery path before you need it.

The personal profile deliberately excludes Remote/SSH/phone activation, unattended executable
updates, Grok CLI credential reuse and Google Antigravity subscription reuse. Normal Google API
keys remain supported. Native Anthropic credentials
stay bound to `api.anthropic.com`; built-in ChatGPT credentials stay bound to `chatgpt.com`.

The personal dashboard exposes only Status, Providers, Desktop, Logs and About. Provider/model
saves do not rewrite Claude settings. Model-slot replacement, custom safety classifiers,
Codex setup, remote/phone control and mod configuration are hidden and guarded; the default-
connection recovery control remains usable when the router is offline.
With the personal picker enabled, prompt markers and old worker/compaction rules cannot override
the selected extra. A failure stays visible on that selected model; no other model is silently
chosen. Disconnecting also preserves non-proxy Desktop settings changed while the integration
was active, using a clean native copy when needed and retaining the original native file.
Personal startup does not run remote tunnels, an OpenAI-compatible API listener, background model
or effort probes, automatic source checks, power/network controllers, Codex catalogue maintenance,
or global Claude worker/context-setting maintenance. These features are not needed for this
Desktop path. Explicit Google connection/model checks in Providers remain available.
Per-model endpoint overrides cannot redirect a provider's credential to another origin.
Production request/diagnostic history is RAM-only in this mode; do not expect it after restart.

## 7. Pause, recover, upgrade or remove

To leave the proxy path even if the router is down:

```powershell
node dist/cli/src/index.js direct on
```

Read its result, then fully quit/reopen Claude Desktop and start new Code sessions. This removes
only proven-owned settings and retains a restoration snapshot. It does not revoke upstream
accounts, stop the router, erase credentials, remove an optional CA trust entry, or change a
different installation's settings. An ownership conflict is a refusal, not permission to force
the transition.

`direct off` restores only after the current source/runtime has been verified. `repair` can repair
owned service registration or stale ports, but cannot turn an unverified live process into an
approved one. Use `install` from the reviewed checkout to verify a deliberate code switch.

An older installation may have recorded a corporate proxy as the original Desktop connection.
`direct on` can restore that recorded connection. Resuming Ripple then refuses to replace it,
including with `--force`, and retains the restoration snapshot for review. Keep using the original
connection until that conflict is resolved; do not remove a corporate proxy or PAC setting just
to bypass the refusal.

Personal mode blocks executable `update`, including `--force`; `update --check` is informational.
To upgrade, first use this known installation's `direct on` and `stop`, close its dashboard, and
confirm it stopped. Review a new exact commit, check out and rebuild that commit, then run
`install` and recheck `doctor`. Do not overwrite running source files, use `git pull` as approval,
or return to the upstream one-line installer. Old code may not understand migrated DPAPI state.

To uninstall the trial, run `uninstall` from this same checkout and with the same data home.
It removes owned integrations and attempts to stop/remove its service; read any ownership or
certificate-removal refusal. The default keeps the data directory. Do not use `--purge` until
cleanup is confirmed and you deliberately want to erase the retained state. Review the picker
CA trust removal result as part of cleanup.

## Verification boundary

Automated tests exercise real local TLS identity checks, Windows ACL/DPAPI paths where native
Windows runs them, startup/refusal logic, source changes with equal version numbers, private-key
retargeting prevention, explicit-origin policy and rollback ownership. A passing test on one
commit does not approve a later commit. The actual scheduled-task installation, your specific
Claude Desktop build, your provider permissions/billing, and concurrent Opus/Google sessions
must still pass the small personal acceptance test above. No test here uses your real account.
