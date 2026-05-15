# Isolated Computer Providers Master Guide

Owner: agent runtime / daemon / sandbox / Autopilot workflow compositor

Status: future-platform leg, ready for implementation

Created: 2026-05-15

## Executive Verdict

The completed local computer-use leg proved IOI's three-lane harness shape with
native browser, visual GUI, and deterministic sandbox fixture paths. The next
provider leg is not only "hosted VM providers." The right abstraction is:

> Isolated computer providers are any leased computer environment that is not
> the current application, browser, or desktop instance.

That includes a local container, a local VM, a cloud container or VM, a tunneled
cloud worker reached by a local daemon, a mobile emulator, a device farm, or a
customer/VPC hosted worker. It also includes task-scoped owned browser profiles
used to inspect local apps without touching the user's daily browser state. Local
vs cloud is deployment topology. The runtime contract is the same: lease,
observe, target, propose, act, verify, retain, clean up.

## Doctrine

- No second runtime.
- No provider-owned action language as runtime truth.
- The daemon owns leases, authority, receipts, artifacts, trajectories, and
  cleanup.
- Local daemon, cloud daemon, and tunneled cloud workers must expose the same
  contract.
- React Flow configures and projects provider choices; it does not own provider
  state.
- A provider may execute actions, but IOI owns `ActionProposal`,
  `ComputerAction`, `ActionReceipt`, `VerificationReceipt`, and
  `TrajectoryBundle`.
- Owned browser sessions must use task-scoped profiles or provider-managed user
  data directories unless the user explicitly grants an attached-profile lease.
- Evidence belongs in declared artifact locations, ignored/generated evidence
  paths, or external temp paths. It must not silently dirty the repo.

## Provider Taxonomy

| Provider shape | Status | Purpose |
| --- | --- | --- |
| `local_fixture` | Done / regression guarded | Deterministic proof path for runtime truth, UI projection, fail-closed behavior, and scorecard coverage. |
| `task_scoped_browser_profile` | P0 parity target | Owned Chromium/Firefox/WebKit session with isolated user-data-dir for inspecting local apps and web UIs without contaminating user browser state. |
| `task_scoped_playwright_context` | P0 adapter candidate | Playwright-backed browser context/page/locator provider for web and local-web-app tasks with trace, screenshot, console, network, and cross-browser artifacts mapped into IOI receipts. |
| `local_container` | P0 next | Docker/Podman/containerd-backed isolated browser or desktop task runner on the current host. |
| `local_vm` | P1 | QEMU, Firecracker, Apple Virtualization, Hyper-V, or equivalent local VM runner. |
| `cloud_container` | P1 | Autopilot cloud or customer cloud container worker using the same daemon contract. |
| `cloud_vm` | P1 | Cloud VM worker for richer OS/browser/app tasks. |
| `tunneled_cloud_worker` | P1 | Local daemon brokers a lease to cloud compute while preserving local policy, receipts, and artifact refs. |
| `mobile_emulator` | P2 | Android emulator, iOS simulator where available, or mobile browser/device automation. |
| `device_provider` | P2 | Real-device farm or BYOI device provider behind explicit trust, retention, and cleanup policy. |

## Contract Spine

Every provider must compile to the same IOI objects:

- `ComputerUseLease`
- `ComputerControlAdapterContract`
- `ComputerUseObservationBundle`
- `TargetIndex`
- `AffordanceGraph`
- `ActionProposal`
- `ComputerAction`
- `ActionReceipt`
- `ComputerUseVerificationReceipt`
- `ComputerUseTrajectoryBundle`
- `CleanupReceipt`
- `ComputerUseRunState`
- `EnvironmentSelectionReceipt`
- `RecoveryPolicy`
- `HumanHandoffState`
- `OutcomeContract`
- `CommitGate`
- `ObservationRetentionMode`

Provider-specific fields live under typed adapter metadata. They must not alter
the canonical action or receipt semantics.

## Target Architecture

The daemon should expose a provider registry and lease manager:

```text
provider_discovery
-> capability_report
-> environment_selection
-> lease_acquisition
-> adapter_boot
-> observation_capture
-> action_execution
-> verification
-> artifact_retention
-> trajectory_export
-> cleanup
```

The registry should answer:

- what provider shapes are installed;
- which provider shapes are healthy;
- which authority scopes are required;
- which retention modes are supported;
- which cleanup guarantees exist;
- whether the provider can run headless, visual, browser-only, desktop, or
  mobile tasks;
- whether missing credentials, missing runtime, or capacity issues are
  fail-closed blockers.

## Reference Pattern: Task-Scoped Autopilot GUI Audit

The target behavior is the same methodology proved by the recent local GUI
audit session:

```text
user asks to inspect Autopilot UI
-> planner selects browser/GUI lane, not connector lane
-> harness starts Autopilot or attaches to approved running target
-> readiness probe confirms target URL/window
-> owned browser starts with isolated profile/user-data-dir
-> harness navigates to target surface
-> observations capture screenshot, DOM/AX when available, URL, logs, and
   viewport metadata
-> actions inspect or click through real UI surfaces
-> evidence is retained outside git or under ignored evidence paths
-> target process, browser process, profile, and port lease are cleaned up
```

This pattern is a first-class parity target because it demonstrates three IOI
properties at once:

- the runtime can route to the correct computer-use lane;
- the harness has the tools to operate the actual product surface;
- user browser/profile state remains untouched.

Playwright should be evaluated as the preferred high-level adapter for this
pattern. Its context/page/locator/trace model can provide stronger web-app
ergonomics than raw CDP for many tasks, while raw CDP/chromiumoxide remains
valuable for lower-level protocol control, BrowserGym/browser-use target
indexing, and environments where Playwright is unavailable.

Required receipts:

- `EnvironmentSelectionReceipt` with selected lane and rejected alternatives;
- `ComputerUseLease` for app target, browser profile, port, and evidence path;
- `ObservationBundle` with screenshot and semantic observations when available;
- `ActionReceipt` for each click, navigation, or inspection action;
- `VerificationReceipt` for expected UI state;
- `CleanupReceipt` for target app, browser process, profile, port, and artifacts.

Fail-closed blockers:

- target app cannot start or readiness probe fails;
- no supported browser engine is available;
- isolated profile cannot be created;
- evidence path would dirty tracked source files;
- cleanup guarantee cannot be established;
- requested action requires attached user profile without explicit approval.

## P0 Slice: Task-Scoped Browser Profile Provider

The first isolation provider should be `task_scoped_browser_profile`, because it
exercises real GUI/browser control immediately and matches the proven local
Autopilot audit method.

Minimum behavior:

1. Create a unique task-scoped browser profile or user-data-dir.
2. Launch Chromium, Firefox, or WebKit against an approved URL/window target.
3. Optionally start a local target app with command, environment policy,
   readiness probe, port lease, and shutdown behavior.
4. Capture screenshot, URL, viewport, console/logs, DOM, and AX observations
   when available.
5. Execute bounded navigation, click, keyboard, and inspection actions.
6. Retain evidence outside git or under ignored evidence paths.
7. Emit environment-selection, lease, action, verification, trajectory, and
   cleanup receipts.
8. Prove user browser profile history, cookies, cache, and extension state were
   not touched.
9. Fail closed when target startup, profile creation, browser launch, evidence
   retention, or cleanup is unsafe.

## P0 Slice: Playwright Context Adapter

The Playwright adapter should run in parallel with the task-scoped browser
profile provider. It is not a replacement for IOI's CDP/browser-use stack; it is
a high-leverage adapter for reliability, cross-browser validation, locators, and
trace capture.

Minimum behavior:

1. Launch Chromium, Firefox, or WebKit through Playwright when installed.
2. Create an isolated `BrowserContext` for each IOI lease.
3. Support non-persistent contexts by default and persistent user-data-dir
   contexts only under explicit policy.
4. Navigate to approved targets and expose URL/title/viewport observations.
5. Convert Playwright locators into IOI target refs and target-index entries.
6. Execute bounded click, fill/type, key, select, hover, screenshot, and wait
   actions after IOI policy and action-proposal checks.
7. Capture screenshots, trace zip, console logs, network summaries, and action
   errors as evidence artifacts.
8. Emit cleanup receipts for context, browser, trace, and retained artifacts.
9. Degrade cleanly when Playwright, browser binaries, or sandbox permissions are
   unavailable.

Fork posture:

- default to adapter usage and upstream-compatible extension points;
- do not fork for convenience;
- fork only after a written blocker proves upstream Playwright cannot expose the
  deterministic evidence, protocol access, or containment semantics IOI needs.

## P1 Slice: Local Container Provider

The first heavier isolated compute provider should be `local_container`, because
it closes the "hosted" deferral without requiring external credentials after the
task-scoped browser profile provider proves the local GUI lease pattern.

Minimum behavior:

1. Discover Docker/Podman/containerd availability without starting a task.
2. Register `local_container` capability with daemon provider discovery.
3. Accept a sandbox task manifest with image, command, browser mode, network
   posture, mounts, artifact retention, and timeout.
4. Acquire a `ComputerUseLease`.
5. Start the container with least-privilege defaults.
6. Capture observation through browser/AX/screenshot channels when available.
7. Execute only approved or read-only actions.
8. Emit action, verification, trajectory, and cleanup receipts.
9. Fail closed when the container runtime, image, network policy, or cleanup
   guarantee is unavailable.

## Workflow Projection

React Flow should keep one canonical `Sandboxed Computer` primitive with config:

- provider: `local_fixture`, `local_container`, `local_vm`, `cloud_container`,
  `cloud_vm`, `mobile_emulator`, `device_provider`;
- image or environment ref;
- task ref;
- network policy;
- mount policy;
- retention mode;
- approval policy;
- cleanup policy;
- budget and timeout.

React Flow should also expose an advanced-but-usable `Browser / Computer`
primitive for task-scoped local GUI work with config:

- target mode: start app / attach approved URL / attach approved window;
- start command and readiness probe;
- browser engine;
- adapter: CDP/chromiumoxide / Playwright / visual fallback / auto;
- isolated profile policy;
- URL or window selector;
- evidence retention path;
- allowed action set;
- cleanup policy;
- approval policy for attached user-profile access.

Advanced/debug inspectors may expose provider-native logs, process ids, image
digests, tunnel ids, and VM/container metadata. Those are evidence, not runtime
truth.

## Autopilot Workbench

Autopilot should show:

- selected provider and rejected alternatives;
- lease id and provider capability report;
- boot/provision status;
- observation bundle and target index;
- action proposal and policy decision;
- executed action or fail-closed blocker;
- verification receipt;
- retained artifacts;
- cleanup receipt;
- provider logs as secondary evidence.

## Validation Plan

Required tests:

- task-scoped browser profile smoke launches an approved target URL, captures
  observation evidence, performs at least one bounded action, and cleans up;
- Playwright context smoke launches an isolated context, uses a semantic
  locator, captures trace/screenshot evidence, emits IOI receipts, and closes
  cleanly;
- Playwright degraded-readiness test reports missing dependency/browser binaries
  without failing unrelated lanes;
- profile contamination guard proves default browser history, cookies, cache,
  and profile directories are untouched;
- target app lifecycle smoke starts a local app, waits for readiness, records
  observations, and stops the app;
- provider registry reports `local_fixture` and `local_container` independently;
- unavailable container runtime fails closed with recovery policy;
- local container smoke emits lease, observation, target index, action,
  verification, trajectory, and cleanup receipts;
- React Flow `Sandboxed Computer` config compiles to provider manifest;
- CLI/TUI can run provider discovery and local container smoke;
- Autopilot run inspector shows provider capability, lease, action,
  verification, cleanup, and blocker rows;
- scorecard distinguishes fixture proof from concrete provider proof.

## Definition Of Done

This leg is complete when:

- `task_scoped_browser_profile` is a concrete provider for local GUI/browser
  audits;
- `task_scoped_playwright_context` is either concrete and regression guarded or
  narrowly deferred with a documented blocker;
- local Autopilot or fixture GUI can be launched, inspected, evidenced, and
  cleaned up without contaminating user browser state;
- `local_container` is a concrete provider, not a fixture;
- provider discovery is daemon/API/SDK/CLI/TUI visible;
- provider leases fail closed without installed runtime, trust, budget, or
  cleanup guarantees;
- React Flow can configure provider selection without shadow state;
- Autopilot shows provider lifecycle and evidence in the run workbench;
- the tri-lane scorecard can report concrete isolated-provider coverage
  separately from deterministic fixture coverage;
- cloud, VM, and mobile providers have narrow, explicit follow-on entries.
