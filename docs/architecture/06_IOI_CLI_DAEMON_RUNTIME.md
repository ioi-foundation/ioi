# IOI CLI / Daemon Runtime Specification

## Canonical Definition

**The IOI CLI/daemon is the universal execution endpoint for canonical Web4 work.**

It runs workflows, agents, workers, tools, models, connectors, and artifact-producing jobs across local, hosted, provider, DePIN, TEE, and enterprise environments.

## Runtime Role

The daemon executes work. It does not own root authority or global marketplace state.

It is responsible for:

- starting runs;
- pausing/resuming/canceling runs;
- executing workflow nodes;
- invoking model router;
- calling tools/connectors;
- producing artifacts;
- emitting events and receipts;
- enforcing policy/firewall gates;
- requesting wallet capabilities;
- syncing outputs to Agentgres;
- fetching packages from Filecoin/CAS;
- streaming status to apps.

## Deployment Targets

1. **Local Autopilot daemon** — desktop/private execution.
2. **Hosted IOI daemon** — always-on hosted workers/services.
3. **Provider daemon** — service provider infrastructure.
4. **DePIN daemon** — Akash-like public compute.
5. **TEE-verified daemon** — enterprise secure mode.
6. **Customer VPC daemon** — enterprise private runtime.

## Public Runtime API

Minimum API surface:

```http
GET  /v1/runtime/manifest
GET  /v1/runtime/health
POST /v1/workers/install
GET  /v1/workers/{id}
POST /v1/runs
GET  /v1/runs/{id}
GET  /v1/runs/{id}/events
GET  /v1/runs/{id}/artifacts
GET  /v1/runs/{id}/receipts
POST /v1/runs/{id}/pause
POST /v1/runs/{id}/resume
POST /v1/runs/{id}/cancel
GET  /v1/deliveries/{id}
```

CLI surface should mirror the API:

```bash
ioi agent run <goal>
ioi agent status <run_id>
ioi agent events <run_id>
ioi agent trace <run_id>
ioi agent export <run_id>
ioi agent verify <run_id>
ioi agent approve <run_id> <request_hash>
ioi agent cancel <run_id>
ioi runtime doctor
ioi tools list
ioi models list
```

## Runtime Envelopes

The daemon should use stable envelopes:

```text
RunRequest
TaskCapsule
RuntimeToolContract
AgentRuntimeEvent
CapabilityRequest
PolicyDecision
ModelInvocationReceipt
ToolExecutionReceipt
ArtifactRef
ReceiptBundle
DeliveryBundle
QualityRecord
```

These envelopes must be stable across local, hosted, marketplace, CLI, UI, workflow, and benchmark surfaces.

## Event Model

The daemon should emit typed replayable events:

```text
session.started
turn.started
context.prepared
model.requested
model.completed
tool.proposed
policy.decided
approval.requested
tool.started
tool.progress
tool.completed
artifact.created
receipt.emitted
run.completed
run.failed
run.cancelled
```

Events are not canonical by themselves; persisted settlement state and receipts are authoritative.

## Relationship to Agentgres

The daemon writes/updates domain state through Agentgres-compatible APIs:

- run state;
- artifacts;
- receipts;
- delivery bundles;
- quality ledgers;
- worker invocations;
- contribution receipts.

The daemon must not maintain a separate canonical state store for application truth.

## Relationship to wallet.network

The daemon requests capabilities from wallet.network.

It must not receive raw long-lived secrets where a scoped capability or operation-internal execution is possible.

Sensitive actions require:

- policy decision;
- capability lease;
- approval token when needed;
- exact request hash;
- expiry;
- revocation epoch.

## Runtime Privacy Modes

1. **Local/private** — local Autopilot, customer machine.
2. **Mutual Blind** — no TEE; redacted/minimized capsules, no final authority.
3. **Enterprise Secure** — TEE-attested node; sealed secret release.
4. **Hosted trusted** — IOI/provider-managed runtime under contractual trust.

## Invariants

1. No effectful tool execution without a tool contract and risk class.
2. No sensitive action without a persisted policy decision.
3. No policy-required approval without exact-scope approval token.
4. No raw secret exposure to agents.
5. No final effect from untrusted DePIN nodes without trusted verification/settlement.
6. No split runtime path for workflow vs agent vs benchmark vs CLI execution.
7. No long-running job without deadline, cancellation, and progress events.

## One-Line Doctrine

> **The IOI daemon is where Web4 work executes; Agentgres remembers it, wallet.network authorizes it, and IOI L1 settles what matters.**

