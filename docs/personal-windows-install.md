# Personal Windows trial from the reviewed security fork

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

## 2. Build the native dashboard without installing a service yet

```powershell
npm.cmd ci --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency installation failed.' }

# Explicitly download the locked Electron runtime. This is the reviewed package's downloader,
# not an upstream ClaudeRipple installer. A skipped or blocked download must be resolved first.
node node_modules/electron/install.js
if ($LASTEXITCODE -ne 0) { throw 'Electron runtime download failed.' }

npm.cmd run build
if ($LASTEXITCODE -ne 0) { throw 'Build failed. Do not install a partially built checkout.' }

node packages/cli/src/index.ts --help
if ($LASTEXITCODE -ne 0) { throw 'The checkout CLI could not run.' }
```

The first two commands fetch dependencies and Electron, so they require internet access. A
corporate registry, custom Electron mirror, or download-blocking policy needs its own review.
Do not respond to download or TLS errors by turning verification off. Keep the checkout in place:
the scheduled task and dashboard launcher will reference these files.

## 3. Approve the destinations you actually intend to use

Personal mode starts with an empty destination allowlist. Approval means that prompts, tool output,
code and the relevant credential **may be sent to that exact HTTPS origin** when you use it.
Approval does not grant an API subscription or waive the provider's data-use terms.

To retain normal Claude/Opus traffic and allow the installer's credential-free connection probe:

```powershell
node packages/cli/src/index.ts security approve-origin https://api.anthropic.com --acknowledge-data-sharing
if ($LASTEXITCODE -ne 0) { throw 'Native Claude destination approval failed.' }
```

If you choose to use your Google AI Studio API key directly, approve its API origin separately:

```powershell
node packages/cli/src/index.ts security approve-origin https://generativelanguage.googleapis.com --acknowledge-data-sharing
if ($LASTEXITCODE -ne 0) { throw 'Google API destination approval failed.' }
```

For a UofT-provided, OpenAI-compatible API, approve the exact origin supplied by the university
instead, for example `https://api.ai.utoronto.ca` for an endpoint below
`https://api.ai.utoronto.ca/v1`. Use the university-issued credential for that endpoint. A Google
AI Studio key is not interchangeable with a university gateway credential.

No wildcard, HTTP URL, user-info component, query or API path belongs in this approval command.
Only approve origins whose owner and purpose you have checked. Additional OAuth destinations,
if a supported login needs them, require their own explicit approval. Do not broadly approve
domains in response to a failed login.

## 4. Install and open the native dashboard

```powershell
node packages/cli/src/index.ts install
if ($LASTEXITCODE -ne 0) { throw 'Installation is incomplete. Read the refusal before retrying.' }

node packages/cli/src/index.ts doctor --json
if ($LASTEXITCODE -ne 0) { throw 'The diagnostic command failed.' }

node packages/cli/src/index.ts ui
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

With picker mode left off, the ordinary setup changes are:

| Area | Change |
| --- | --- |
| Personal data directory | Owner-private local keys/state; DPAPI-protected provider-credential/config storage, bound to this Windows user |
| Diagnostics | Bounded RAM history while the router runs; headless task and tray subprocesses do not write their stdout/stderr to durable log files |
| Task Scheduler | An owned `ClaudeRippleRouter` logon task, using the interactive user with limited privileges |
| Claude Code settings | Owned `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` entries, with a backup and ownership record |
| Local listeners | Loopback proxy plus authenticated, certificate-pinned local admin TLS; no privileged browser dashboard |
| App launcher | Per-user shortcuts that open this source build's native dashboard |

The task uses a child PowerShell invocation with a process-specific execution-policy argument;
it does not require changing the system's permanent execution policy. The dedicated admin CA is
not imported into the Windows trust store. **Do not enable picker mode for the initial trial**:
that optional mode additionally trusts the proxy CA in the current user's root store and routes
Claude Desktop's broader app traffic through the proxy.

## 5. Configure and test the two-session use case

In the native dashboard, add the Google API-key provider, or your explicitly approved university
gateway. Use a separate, limited key where the provider supports one. Enter it in the native UI,
not in a shell command, issue, screenshot or chat message. Use an actual model ID available to
your account; a display name such as “Carbon” does not establish an API model ID or availability.

Keep the native Opus choice on normal Claude passthrough. Map a separate selectable slot to the
Google/gateway model. The displayed Claude slot name can be an alias: confirm the destination and
actual model in the dashboard's request details. Start fresh Code sessions after changing slots.
The precise current Desktop picker behaviour still needs a real-account acceptance test.

Use an empty, disposable project for the first run:

1. In one new session, select native Opus and request a short text answer. Confirm native routing.
2. In a second session, select the mapped slot and request another short answer. Confirm the
   expected approved provider and actual model, with no fallback to a different origin.
3. Allow a harmless file-read request, inspect a proposed edit before approving it, and test cancel.
   Keep the agent's normal tool/command approval controls enabled.
4. Revoke the optional provider origin, confirm that a new provider request is refused, then
   explicitly approve it again only if you want to resume. This checks the relevant boundary
   without using private research files or production credentials.

The personal profile deliberately excludes Remote/SSH/phone activation, unattended executable
updates, Grok CLI credential reuse and Google Antigravity subscription reuse. Normal Google API
keys and an explicitly configured university API remain supported. Native Anthropic credentials
stay bound to `api.anthropic.com`; built-in ChatGPT credentials stay bound to `chatgpt.com`.
Per-model endpoint overrides cannot redirect a provider's credential to another origin.
Production request/diagnostic history is RAM-only in this mode; do not expect it after restart.

## 6. Pause, recover, upgrade or remove

To leave the proxy path even if the router is down:

```powershell
node packages/cli/src/index.ts direct on
```

Read its result, then fully quit/reopen Claude Desktop and start new Code sessions. This removes
only proven-owned settings and retains a restoration snapshot. It does not revoke upstream
accounts, stop the router, erase credentials, remove an optional CA trust entry, or change a
different installation's settings. An ownership conflict is a refusal, not permission to force
the transition.

`direct off` restores only after the current source/runtime has been verified. `repair` can repair
owned service registration or stale ports, but cannot turn an unverified live process into an
approved one. Use `install` from the reviewed checkout to verify a deliberate code switch.

Personal mode blocks executable `update`, including `--force`; `update --check` is informational.
To upgrade, first use this known installation's `direct on` and `stop`, close its dashboard, and
confirm it stopped. Review a new exact commit, check out and rebuild that commit, then run
`install` and recheck `doctor`. Do not overwrite running source files, use `git pull` as approval,
or return to the upstream one-line installer. Old code may not understand migrated DPAPI state.

To uninstall the trial, run `uninstall` from this same checkout and with the same data home.
It removes owned integrations and attempts to stop/remove its service; read any ownership or
certificate-removal refusal. The default keeps the data directory. Do not use `--purge` until
cleanup is confirmed and you deliberately want to erase the retained state. Review any optional
picker CA separately if you enabled picker mode during later testing.

## Verification boundary

Automated tests exercise real local TLS identity checks, Windows ACL/DPAPI paths where native
Windows runs them, startup/refusal logic, source changes with equal version numbers, private-key
retargeting prevention, explicit-origin policy and rollback ownership. A passing test on one
commit does not approve a later commit. The actual scheduled-task installation, your specific
Claude Desktop build, your provider permissions/billing, and concurrent Opus/Google sessions
must still pass the small personal acceptance test above. No test here uses your real account.
