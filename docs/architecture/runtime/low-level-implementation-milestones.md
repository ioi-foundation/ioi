# Low-Level Implementation Milestones

Status: canonical low-level roadmap.
Canonical owner: this file for low-level milestone sequencing and cross-surface proof gates.
Supersedes: overlapping implementation milestone lists when low-level proof gates conflict.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This file gives a chronological implementation order for the v2 APIs and low-level surfaces.

## Milestone A — Canonical Envelope Foundation

Build:

```text
ManifestEnvelope
AuthorityScopeRequestEnvelope
AuthorityGrantEnvelope
TaskEnvelope
RunEnvelope
RuntimeEventEnvelope
ReceiptEnvelope
ArtifactEnvelope
DeliveryEnvelope
ContributionEnvelope
```

Exit criteria:

```text
All runtime, marketplace, wallet, and Agentgres APIs use shared IDs and envelope fields.
```

## Milestone B — IOI Daemon Runtime API

Build:

```text
/v1/runtime/manifest
/v1/agents
/v1/agents/{id}/runs
/v1/runs
/v1/runs/{id}/events
/v1/runs/{id}/artifacts
/v1/runs/{id}/receipts
/v1/runs/{id}/trace
/v1/runs/{id}/inspect
/v1/runs/{id}/scorecard
/v1/tools
/v1/models
/v1/repositories
/v1/account
/v1/runtime/nodes
/v1/connectors
```

Exit criteria:

```text
A run can be started, observed, replayed, tailed, paused, approved, resumed, cancelled, completed, exported, inspected, scored, and verified through SDK, CLI, GUI, workflow compositor, harness, and benchmark clients without creating separate runtimes.
```

## Milestone C — wallet.network Authority Scope Core

Build:

```text
authority scope request/grant/revoke
approval request/approve/deny
BYOK secret brokerage
connector credential brokerage
payment authorization
emergency stop
primitive capability admission metadata
```

Exit criteria:

```text
No agent or runtime needs raw long-lived secrets for model or connector use.
```

## Milestone D — Agentgres Domain Core

Build:

```text
domain manifest
operations
objects/history
runtime operation log
run/task/task-state objects
policy/authority decision objects
stop-condition objects
scorecard/quality objects
patch lifecycle
query/projection/subscription
artifact/receipt refs
settlement mirror
```

Exit criteria:

```text
aiagent.xyz, sas.xyz, or a local daemon can persist canonical operational state without touching IOI L1 per operation. SDK checkpoints, GUI stores, CLI session files, harness fixtures, and workflow caches are non-authoritative projections or exports.
```

## Milestone E — aiagent.xyz Worker Marketplace API

Build:

```text
worker listing
worker manifest fetch
install
invoke
hosted run
persistent worker profile
inter-agent endpoints
quality ledger projection
contribution receipts
```

Exit criteria:

```text
A user can install or run a worker locally or hosted and receive artifacts/receipts.
```

## Milestone F — sas.xyz Service Marketplace API

Build:

```text
service listing
service order
escrow mirror
delivery bundle
accept/revision/dispute
provider publish/claim/deliver
```

Exit criteria:

```text
A user can buy an outcome without Autopilot installed and receive a verified delivery bundle.
```

## Milestone G — IOI L1 Contract Suite

Build:

```text
AiNamespaceRegistry
PublisherRegistry
ManifestRootRegistry
WorkerRegistry
ServiceRegistry
LicenseRightRegistry
ServiceOrderEscrow
SLABondRegistry
DisputeRegistry
ReputationRootRegistry
ContributionRootRegistry
RuntimeProviderRegistry
```

Exit criteria:

```text
Rights, registry, escrow, settlement, bonds, disputes, and sparse roots live on IOI L1.
```

## Milestone H — Filecoin/CAS Package and Artifact Plane

Build:

```text
artifact init/upload/commit
package refs
artifact bundles
delivery bundles
trace bundles
hash verification
privacy/encryption metadata
```

Exit criteria:

```text
Workers, services, artifacts, and evidence can be fetched from CDN/Filecoin and verified by hash/root.
```

## Milestone I — Runtime Node Scheduling and Privacy Modes

Build:

```text
task capsule
runtime assignment
mutual blind execution
TEE attestation envelope
sealed secret release
remote result envelope
```

Exit criteria:

```text
A run can be assigned to local, hosted, DePIN mutual blind, or TEE enterprise node by policy.
```

## Milestone J — Marketplace Neutrality Enforcement

Build:

```text
routing decision record
usage receipt
contribution receipt
attribution graph
license envelope
quality delta
reward claim
```

Exit criteria:

```text
The default harness can recommend or invoke marketplace workers without silently appropriating them.
```

## Milestone K — Model Router and Connector Registry

Build:

```text
model endpoint registry
BYOK provider keys through wallet.network
local model mounting
run-to-idle lifecycle
connector tool contracts
risk classes
approval requirements
```

Exit criteria:

```text
Workflows call model/tool routes through primitive capabilities, authority scopes, and policy, not hardcoded provider flags.
```

## Milestone L — Smarter Agent Runtime Loop

Build:

```text
TaskStateModel
UncertaintyAssessment
Probe
PostconditionSynthesizer
SemanticImpactAnalysis
CapabilityDiscovery/Selection/Sequencing/Retirement
CognitiveBudget
DriftSignal
StopCondition
HandoffQuality
VerifierIndependencePolicy
MemoryQualityGate
OperatorPreference
TaskFamilyPlaybook
NegativeLearningRecord
AgentQualityLedger
BoundedSelfImprovementGate
```

Exit criteria:

```text
The records above influence routing, verification, recovery, stopping, handoff, memory writes, model/tool selection, or quality scoring in SDK, CLI, GUI, harness, and workflow-compositor paths.
```

## Milestone M — Cross-Surface Execution Proof

Build:

```text
one retained objective through SDK
same retained objective through CLI
same retained objective through GUI
same retained objective through workflow compositor
same retained objective through harness
same retained objective through benchmark/scorecard path
Agentgres replay/export
trace/receipt/scorecard compatibility report
hosted/self-hosted smoke or exact external blocker evidence
```

Exit criteria:

```text
All surfaces produce compatible run IDs or linked lineage, event cursors, terminal state, stop reason, task-state projection, receipts, trace export, replay result, quality ledger, and scorecard.
```

## Final Low-Level Readiness Test

A complete test should prove:

```text
1. User orders a sas.xyz service in browser.
2. Escrow is locked on IOI L1.
3. sas.xyz Agentgres creates operational order state.
4. Runtime router assigns an IOI daemon node.
5. Node fetches package/artifacts from Filecoin/CAS.
6. Runtime admits primitive capabilities and wallet.network grants authority scopes.
7. Runtime executes and streams events.
8. Artifacts and receipts are emitted.
9. Delivery bundle is recorded in Agentgres.
10. User accepts delivery.
11. IOI L1 releases payout.
12. Contribution and quality roots are updated.
```
