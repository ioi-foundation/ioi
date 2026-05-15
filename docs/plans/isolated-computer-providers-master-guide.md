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
customer/VPC hosted worker. Local vs cloud is deployment topology. The runtime
contract is the same: lease, observe, target, propose, act, verify, retain,
clean up.

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

## Provider Taxonomy

| Provider shape | Status | Purpose |
| --- | --- | --- |
| `local_fixture` | Done / regression guarded | Deterministic proof path for runtime truth, UI projection, fail-closed behavior, and scorecard coverage. |
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

## P0 Slice: Local Container Provider

The first real provider should be `local_container`, because it closes the
"hosted" deferral without requiring external credentials.

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

- `local_container` is a concrete provider, not a fixture;
- provider discovery is daemon/API/SDK/CLI/TUI visible;
- provider leases fail closed without installed runtime, trust, budget, or
  cleanup guarantees;
- React Flow can configure provider selection without shadow state;
- Autopilot shows provider lifecycle and evidence in the run workbench;
- the tri-lane scorecard can report concrete isolated-provider coverage
  separately from deterministic fixture coverage;
- cloud, VM, and mobile providers have narrow, explicit follow-on entries.
