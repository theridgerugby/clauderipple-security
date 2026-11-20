# This personal security fork is installed only from a reviewed, fixed source checkout.
# Stop before downloads, runtime changes, settings, PATH or service registration.
[Console]::Error.WriteLine('This personal security fork disables bootstrap installation. Follow docs/personal-windows-install.md at the reviewed commit.')
exit 1
# LEGACY_INSTALLER_BODY: retained for isolated regression fixtures; unreachable in this fork.
# ClaudeRipple installer for Windows.
#
# Run a reviewed local copy from the intended release: powershell -File .\install.ps1
#
# Installing from npm needs npm, which needs Node, which is the one thing a first-time user is not
# guaranteed to have. So this script brings its own: it uses a Node 24+ already on PATH when there
# is one, and otherwise downloads the official build into ClaudeRipple's own directory. Nothing
# here needs administrator rights, and nothing is written outside the prefix and the user's PATH.
#
# Options (environment):
#   CLAUDERIPPLE_PREFIX    where to install            (default: $HOME\.clauderipple)
#   CLAUDERIPPLE_PACKAGE   what to install             (default: clauderipple, from npm)
#   CLAUDERIPPLE_NO_SETUP  1 = install only, no setup  (default: run `clauderipple install`)
#   CLAUDERIPPLE_NO_TRAY   1 = do not add the menu-bar app (Electron is ~270MB)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Prefix = if ($env:CLAUDERIPPLE_PREFIX) { $env:CLAUDERIPPLE_PREFIX } else { Join-Path $HOME '.clauderipple' }
$Package = if ($env:CLAUDERIPPLE_PACKAGE) { $env:CLAUDERIPPLE_PACKAGE } else { 'clauderipple' }
$NodeMajor = 24
# Resolved from nodejs.org at install time so this script does not carry a version that goes stale;
# the pin is only what to use when the release index cannot be reached.
$NodeFallback = 'v24.21.0'
$Runtime = Join-Path $Prefix 'runtime'
$NodeBackup = $null
$NodeStaging = $null

function Get-NodeMajor([string]$exe) {
  # `node -v` and a regex, not `node -e`: PowerShell 5.1 mangles the quotes inside an -e script, and
  # the resulting SyntaxError on stderr becomes a terminating error under ErrorActionPreference Stop.
  # Measured 2026-09-16 in a Windows 11 arm64 VM: a perfectly good Node 24 was reported as absent and
  # the installer downloaded a second copy.
  $old = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $out = (& $exe -v 2>$null | Out-String).Trim()
    if ($out -match '^v(\d+)\.') { return [int]$Matches[1] }
    return 0
  } catch { return 0 }
  finally { $ErrorActionPreference = $old }
}

function Find-Node {
  $cmd = Get-Command node -ErrorAction SilentlyContinue
  if ($cmd -and (Get-NodeMajor $cmd.Source) -ge $NodeMajor) { return $cmd.Source }
  $own = Join-Path $Runtime 'node.exe'
  if ((Test-Path $own) -and (Get-NodeMajor $own) -ge $NodeMajor) { return $own }
  return $null
}

function Install-Node {
  $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64' }
    'ARM64' { 'arm64' }
    default { throw "unsupported processor: $($env:PROCESSOR_ARCHITECTURE). Install Node $NodeMajor+ yourself, then: npm install -g clauderipple" }
  }
  $version = $NodeFallback
  try {
    $index = Invoke-RestMethod -Uri 'https://nodejs.org/dist/index.json' -UseBasicParsing
    $newest = $index | Where-Object { $_.version -match "^v$NodeMajor\.[0-9]+\.[0-9]+$" } | Select-Object -First 1
    if ($newest) { $version = $newest.version }
  } catch { }

  $name = "node-$version-win-$arch"
  $base = "https://nodejs.org/dist/$version"
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null
  try {
  Write-Host "Downloading Node $version (win-$arch)..."
  $zip = Join-Path $tmp "$name.zip"
  Invoke-WebRequest -Uri "$base/$name.zip" -OutFile $zip -UseBasicParsing
  # The download is verified against the release's own checksum file before anything is unpacked.
  $sums = (Invoke-WebRequest -Uri "$base/SHASUMS256.txt" -UseBasicParsing).Content
  $checksumPattern = '^[0-9a-fA-F]{64}\s+' + [regex]::Escape("$name.zip") + '\s*$'
  $line = ($sums -split "`n" | Where-Object { $_ -match $checksumPattern } | Select-Object -First 1)
  if (-not $line) { throw "no checksum published for $name.zip" }
  $expected = ($line -split '\s+')[0]
  $actual = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $expected.ToLower()) { throw 'the Node download does not match its published checksum' }

  # Unpack and verify before touching a working runtime. Both renames stay on the prefix's
  # filesystem; the backup survives until npm and the command shim have completed successfully.
  New-Item -ItemType Directory -Path (Split-Path $Runtime -Parent) -Force | Out-Null
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $unpacked = Join-Path $tmp $name
  $unpackedNode = Join-Path $unpacked 'node.exe'
  if (-not (Test-Path -LiteralPath $unpackedNode -PathType Leaf) -or (Get-NodeMajor $unpackedNode) -lt $NodeMajor) {
    throw 'the unpacked Node runtime is missing or is not a supported version'
  }
  $script:NodeStaging = "$Runtime.new.$([Guid]::NewGuid().ToString('N'))"
  Move-Item -LiteralPath $unpacked -Destination $script:NodeStaging
  if (Test-Path -LiteralPath $Runtime) {
    $script:NodeBackup = "$Runtime.old.$([Guid]::NewGuid().ToString('N'))"
    Move-Item -LiteralPath $Runtime -Destination $script:NodeBackup
  }
  Move-Item -LiteralPath $script:NodeStaging -Destination $Runtime
  $script:NodeStaging = $null
  } finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Restore-NodeRuntime {
  if ($script:NodeBackup -and (Test-Path -LiteralPath $script:NodeBackup)) {
    if (Test-Path -LiteralPath $Runtime) { Remove-Item -LiteralPath $Runtime -Recurse -Force }
    Move-Item -LiteralPath $script:NodeBackup -Destination $Runtime
    $script:NodeBackup = $null
  }
  if ($script:NodeStaging -and (Test-Path -LiteralPath $script:NodeStaging)) {
    Remove-Item -LiteralPath $script:NodeStaging -Recurse -Force
    $script:NodeStaging = $null
  }
}

try {
# Recover a single old-only copy after an interruption that prevented finally from running.
if (-not (Test-Path -LiteralPath $Runtime) -and (Test-Path -LiteralPath $Prefix)) {
  $oldCopies = @(Get-ChildItem -LiteralPath $Prefix -Directory | Where-Object { $_.Name -like 'runtime.old.*' })
  if ($oldCopies.Count -gt 1) { throw 'multiple previous Node runtimes remain; inspect the installation before retrying' }
  if ($oldCopies.Count -eq 1) { Move-Item -LiteralPath $oldCopies[0].FullName -Destination $Runtime }
}
$node = Find-Node
if ($node) {
  Write-Host "Using Node $(& $node -v) at $node"
} else {
  Install-Node
  $node = Join-Path $Runtime 'node.exe'
  if (-not (Test-Path $node)) { throw "unpacked Node but found no executable at $node" }
  Write-Host "Installed Node $(& $node -v) in $Runtime"
}

$npmCli = Join-Path (Split-Path $node -Parent) 'node_modules\npm\bin\npm-cli.js'
if (-not (Test-Path $npmCli)) {
  $npmCmd = Get-Command npm -ErrorAction SilentlyContinue
  if ($npmCmd) { $npmCli = Join-Path (Split-Path $npmCmd.Source -Parent) 'node_modules\npm\bin\npm-cli.js' }
}
if (-not (Test-Path $npmCli)) { throw "found Node at $node but no npm next to it" }

# Until 0.6 the tray's Electron (~270MB) was fetched into the package's own node_modules, and
# installing any other version deleted it with the old files — or failed, since a running tray
# holds electron.exe open there. It now lives in ClaudeRipple's home; one found in the old place
# is moved there rather than fetched again, and a tray running from it is started again at the end.
$HomeDir = if ($env:CLAUDERIPPLE_HOME) { $env:CLAUDERIPPLE_HOME } else { Join-Path $HOME '.clauderipple' }
$OldElectron = Join-Path $Prefix 'node_modules\clauderipple\node_modules\electron'
$NewElectron = Join-Path $HomeDir 'tray-runtime\node_modules\electron'
$RestartTray = $false
if ((Test-Path $OldElectron) -and -not (Test-Path $NewElectron)) {
  $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($OldElectron, [StringComparison]::OrdinalIgnoreCase) })
  if ($running.Count -gt 0) {
    $running | Stop-Process -Force
    Start-Sleep -Seconds 1
    $RestartTray = $true
  }
  New-Item -ItemType Directory -Force -Path (Split-Path $NewElectron -Parent) | Out-Null
  Move-Item -Path $OldElectron -Destination $NewElectron
  Write-Host "Moved the tray's Electron to $NewElectron"
}

# Installed under our own prefix rather than the Node installation's: nothing to elevate, and
# uninstalling is removing one directory.
Write-Host "Installing $Package..."
& $node $npmCli install --global --prefix $Prefix --registry https://registry.npmjs.org --ignore-scripts --loglevel error $Package
if ($LASTEXITCODE -ne 0) { throw "npm could not install $Package" }

# Record the method even for --no-setup and a prefix chosen only for this invocation.
$installRecord = @{ kind = 'script'; prefix = [System.IO.Path]::GetFullPath($Prefix) } | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText((Join-Path $Prefix 'clauderipple-install.json'), $installRecord, (New-Object System.Text.UTF8Encoding($false)))

# npm's global prefix on Windows puts the commands at the prefix root, not in a bin subdirectory.
$bin = $Prefix
$cmd = Join-Path $bin 'clauderipple.cmd'
if (-not (Test-Path $cmd)) { throw "npm installed $Package but left no command in $bin" }

# npm's own command shims invoke a bare `node`, which resolves to nothing when the Node we just
# downloaded is the only one on this machine: the install succeeds and the command cannot start.
# Measured 2026-09-16 in a Windows 11 arm64 VM. Replaced with shims that name the interpreter.
if ($node.StartsWith($Runtime, [StringComparison]::OrdinalIgnoreCase)) {
  $entry = Join-Path $Prefix 'node_modules\clauderipple\bin\clauderipple.js'
  if (-not (Test-Path $entry)) { throw "the installed package has no entry point at $entry" }
  # cmd.exe reads each line in the active console code page. Switch on an ASCII-only line
  # before it reads the UTF-8 paths; no BOM (cmd would treat it as part of the first command).
  # Percent signs are expanded even inside cmd quotes. Delayed expansion would likewise expand
  # !name! in a path. Escape the former and disable the latter before cmd reads any path.
  $nodeLiteral = $node.Replace('%', '%%')
  $entryLiteral = $entry.Replace('%', '%%')
  $wrapper = "@echo off`r`nsetlocal DisableDelayedExpansion`r`nchcp 65001 >nul`r`n`"$nodeLiteral`" `"$entryLiteral`" %*`r`n"
  [System.IO.File]::WriteAllText($cmd, $wrapper, (New-Object System.Text.UTF8Encoding($false)))
}

# After npm and the shim succeed, retain the new runtime even if later service setup fails.
$committedBackup = $script:NodeBackup
$script:NodeBackup = $null
if ($committedBackup) {
  try { Remove-Item -LiteralPath $committedBackup -Recurse -Force }
  catch { Write-Warning "The new Node runtime is installed; its previous backup could not be removed: $committedBackup" }
}

# PowerShell picks clauderipple.ps1 over clauderipple.cmd, and under the default execution policy
# a .ps1 does not run: `clauderipple ui` failed with PSSecurityException in a new window (#38).
# Without it PowerShell falls through to the .cmd, which runs under any policy.
Remove-Item -Path (Join-Path $bin 'clauderipple.ps1') -Force -ErrorAction SilentlyContinue

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (($userPath -split ';') -notcontains $bin) {
  [Environment]::SetEnvironmentVariable('Path', (($userPath.TrimEnd(';') + ';' + $bin).TrimStart(';')), 'User')
  Write-Host "Added $bin to your PATH. Open a new terminal to pick it up."
}
$env:Path = "$bin;$env:Path"

if ($env:CLAUDERIPPLE_NO_SETUP -eq '1') {
  Write-Host ''
  Write-Host 'Installed. Finish with: clauderipple install'
  exit 0
}

Write-Host ''
& $cmd install
# `install` exits 1 when the router does not answer its end-to-end probe (the scheduled task was
# started, but no router came up). Windows PowerShell 5.1 leaves that code in $LASTEXITCODE and
# carries on, so this script used to end 0 — and print "Open the dashboard…" — over a setup that
# had not brought the router up. An update then looked complete while the version stayed old, and
# only `repair` recovered it (#62, #80). The failure is inherited, not swallowed.
$setupCode = $LASTEXITCODE
if ($setupCode -ne 0) {
  Write-Host ''
  Write-Host "The router could not be set up (install exited with code $setupCode)."
  Write-Host 'Run again: clauderipple.cmd install'
  Write-Host 'If the router still does not start, run: clauderipple.cmd repair'
  exit $setupCode
}

# Part of the default install on Windows: it carries the dashboard that opens with the router down
# (repair, switch to Claude's own connection), which is the entry point a non-terminal user needs.
# Electron is ~270MB, so CLAUDERIPPLE_NO_TRAY=1 skips it.
$trayReady = $false
if ($env:CLAUDERIPPLE_NO_TRAY -ne '1') {
  Write-Host ''
  Write-Host 'Adding the menu-bar app (Electron, about 270MB, fetched once)...'
  & $cmd tray --install
  if ($LASTEXITCODE -eq 0) {
    & $cmd app --install
    if ($LASTEXITCODE -ne 0) { Write-Host "The menu-bar app's launcher was not added; try again with: clauderipple app --install" }
    $trayReady = $true
  } else {
    Write-Host ''
    Write-Host 'The router is installed; the menu-bar app was not. Add it later with: clauderipple tray --install'
  }
}
# Started once: either because the new tray was just installed, or because the old one was stopped
# to move its Electron.
if ($RestartTray -or $trayReady) { & $cmd tray }
Write-Host ''
Write-Host 'Open the dashboard with: clauderipple ui'
} finally {
  Restore-NodeRuntime
}
