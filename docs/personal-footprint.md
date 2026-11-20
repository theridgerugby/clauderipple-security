# Personal Desktop footprint

The personal install has two parts: a supervised local routing process used by Claude Desktop,
and a native setup/recovery window opened only when needed. The setup window does not register
itself at login, create a tray, check for updates in the background, or remain running after its
last window closes. Windows still runs the owned router task and its PowerShell watchdog.
Those are required for the selected Desktop proxy connection to keep working.

## Install and build inventory

Use the exact pinned source and commands in [the Windows guide](personal-windows-install.md).
The workspace filter is part of the installation boundary:

```powershell
npm.cmd ci --workspace @clauderipple/app --include-workspace-root --ignore-scripts
node scripts/check-personal-install.mjs
npm.cmd run build:personal
npm.cmd run smoke:personal
```

The checker verifies manifest/lock agreement and every installed package against the personal
dependency closure. It rejects unexpected packages or links, Remote/Agent SDK, phone, Cloudflare
relay and release-packaging dependencies. The full developer install is intentionally rejected
by this checker; the developer CI suite still uses it to test retained legacy libraries.

The build compiles the CLI/router entrypoint closure, standalone admin bridge and watchdog helper,
and the native setup app. It includes the local UI/assets and only the small imported Remote/mod
helper files. It excludes the Remote host, Remote web app, full mod and installers. Every emitted
runtime import is verified before a recognized generated build is replaced. The runtime uses
`node dist/cli/src/index.js`; no additional TypeScript runner is installed.

Observed clean Linux dependency inventories with Node 24.22.3 and the unchanged locked versions:

| Item | Full developer install | Filtered personal install |
| --- | ---: | ---: |
| Apparent dependency file bytes | 804,444,577 | 37,657,875 |
| Difference | | 95.3% fewer bytes |
| Personal third-party packages | | 31, plus the app workspace link |
| Core router runtime dependency closure | | 5 packages, about 1.8 MB of files |

The five runtime packages are `undici`, `proper-lockfile`, `graceful-fs`, `retry`, and
`signal-exit`. TypeScript, type definitions and Electron's package/downloader are build/setup
dependencies, not continuously running services. Both size measurements **exclude the downloaded
Electron binary**, the Node runtime, source checkout, Git history, npm cache and user data. They
are apparent file sizes, not disk allocation, download size or memory. The native setup window
still requires the separately downloaded, pinned Electron runtime. Windows sizes can differ.

## Router measurement

Before the unused-controller cleanup, three alternating starts compared Node's TypeScript source
execution with the precompiled JavaScript from the same router version. All used synthetic picker
configuration, disposable cached certificates and the same instrumentation. Outgoing sockets,
fetches and child-process starts were blocked and counted; no real key or account was used.

| Measurement | Source TypeScript | Compiled JavaScript |
| --- | ---: | ---: |
| Time to first proxy listener, three runs | 796 / 572 / 618 ms | 328 / 316 / 299 ms |
| Median time to first proxy listener | 618 ms | 316 ms |
| Settled RSS, three runs | 114.2 / 113.9 / 113.9 MiB | 75.9 / 76.5 / 76.2 MiB |
| Median settled RSS | 113.9 MiB | 76.2 MiB |

This is roughly 49% less startup time and 33% less router memory in that Linux experiment.
A separate 10-second idle observation of the compiled router consumed about 11 ms of CPU,
with no observed file operations, external requests or child-process attempts in that window.
These are small controlled samples, not Windows measurements or guarantees about an active
conversation. They exclude the Windows watchdog, Claude Desktop and an open setup window.
Fresh certificate generation, active streams, conversation state and host load affect results.

An independent check of the new filtered compiled build also started an actual picker-enabled
router using only the personal dependencies, with three loopback listeners and a clean shutdown.
The three listeners are the proxy, pinned authenticated admin TLS, and liveness-only HTTP for
the watchdog. Certificate verification, source/runtime fingerprinting, connection deadlines and
owned-process recovery remain enabled. Idle safety scans were not removed to improve a number.

## Acceptance boundary

The ordinary and native Windows CI gates plus the filtered-install/compiled-task job must pass
for the exact commit. The native app tests exercise its real production main entrypoint with
synthetic state, sandboxed rendering, close/quit and refused capabilities. The task tests create
only a uniquely named disposable service and never change an installed Claude application.

The owner's Desktop build, actual dropdown, Google model access and everyday connectors still
need the short harmless-project check in the installation guide. In that check, close setup and
confirm native Claude, Google and the return to native Claude still work. Opening the new setup
window alone does not migrate an older recorded source runtime: the verified compiled `install`
step must complete first. Old unmarked Windows startup entries require explicit ownership review;
this version does not silently delete registry entries or retained logs/backups.
