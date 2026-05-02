# Implementation Roadmap and Dependency Specification

Status: canonical architecture roadmap.
Canonical owner: this file for high-level implementation sequencing; low-level proof gates live in [`low-level-implementation-milestones.md`](./low-level-implementation-milestones.md).
Supersedes: overlapping roadmap prose when phase ordering conflicts.
Superseded by: none.
Last alignment pass: 2026-05-01.

## Purpose

This roadmap orders implementation so product surfaces ship without violating architectural boundaries.

## Strategic Order

```text
Workflow Canvas V1 Hardening
→ Workflow Runtime Parity
→ Harness Componentization
→ Harness-as-Workflow
→ Connector Tool Registry
→ Model Router / BYOK / Local Mounting
→ wallet-core-lite
→ Minimal Persistent Agent State
→ My Agents GUI
→ Agent Office / Project Rooms
→ Agent API
→ Agentgres v0
→ aiagent.xyz Worker Marketplace
→ sas.xyz Service Marketplace
→ Marketplace Neutrality / Contribution Accounting hardening
→ Resource/DePIN/TEE scaling
```

## Phase 0 — Workflow Canvas V1 Hardening

Goal: make workflows product-grade.

Build:

- graph-aware warnings;
- node-specific configuration;
- per-node input/output panes;
- pinned fixtures;
- replay/dry-run;
- activation checklist;
- execution timeline;
- honest runtime status.

Exit:

- users can create, validate, run, debug, and package non-trivial workflows.

## Phase 1 — Workflow Runtime Parity

Goal: visible nodes actually run or honestly block.

Build:

- shared node execution contract;
- trigger/parser/adapter/tool/state/loop/barrier/subgraph/human gate/output behavior;
- subgraph-as-tool;
- approval interrupt/resume;
- runtime event schema.

Exit:

- every UI node maps to runtime behavior or explicit block reason.

## Phase 2 — Harness Componentization

Goal: expose harness primitives as workflow-compatible components.

Components:

- planner;
- model call;
- tool call;
- connector call;
- policy/firewall gate;
- wallet authority scope request;
- memory read/write;
- verifier;
- artifact writer;
- receipt writer;
- retry/repair;
- judge/merge;
- completion gate.

Exit:

- default harness can render as read-only graph.

## Phase 3 — Harness-as-Workflow

Goal: default harness becomes a blessed inspectable template.

Build:

- read-only graph;
- validated fork path;
- model/tool/verifier/approval slots;
- node logs and replay;
- proposal-only self-mutation.

Exit:

- persistent worker can point to harness workflow by ID.

## Phase 4 — Connector Tool Registry

Goal: connectors expose typed tools.

Build:

- `RuntimeToolContract`;
- connector tool registry;
- risk classes;
- schema validation;
- wallet authority scope mapping;
- receipts.

## Phase 5 — Model Router / BYOK / Local Mounting

Goal: model calls route through policy.

Build:

- model registry;
- model router;
- BYOK via wallet.network;
- LM Studio/Ollama/OpenAI-compatible mounting;
- model invocation receipts;
- run-to-idle lifecycle.

## Phase 6 — wallet-core-lite

Goal: safe authority before persistent workers.

Build:

- encrypted local secret store;
- authority scope request API;
- policy envelopes;
- session grants;
- approval tokens;
- revocation;
- audit receipts;
- BYOK brokerage;
- connector credential vault.

## Phase 7 — Minimal Persistent Agent State

Goal: agents become digital workers, not personas.

Objects:

- `AgentDefinition`;
- `AgentInstall`;
- `AgentRun`;
- `AgentToolGrant`;
- `AgentSchedule`;
- `StandingOrder`;
- `AgentInboxItem`;
- `AgentArtifact`;
- `AgentReceipt`.

## Phase 8 — My Agents GUI

Goal: digital employee roster.

Surfaces:

- roster;
- standing orders;
- tool grants;
- model policy;
- schedule;
- memory/context;
- runs;
- inbox;
- artifacts;
- receipts.

## Phase 9 — Agent Office / Project Rooms

Goal: long-duration planner-agent coordination.

Objects:

- `ProjectRoom`;
- `Mission`;
- `Objective`;
- `Decision`;
- `Plan`;
- `StatusUpdate`;
- `Risk`;
- `Blocker`;
- `TaskRequest`;
- `RunSpawn`;
- `Digest`.

## Phase 10 — Agent API

Expose:

```http
GET  /v1/agents
POST /v1/agents/{id}/tasks
GET  /v1/agents/{id}/runs
GET  /v1/agents/{id}/inbox
POST /v1/agents/{id}/standing-orders
POST /v1/interagent/task-offer
POST /v1/interagent/handoff
GET  /v1/artifacts/{id}
GET  /v1/receipts/{id}
```

## Phase 11 — Agentgres v0

Start by replacing Autopilot workflow/agent/run canonical state, not every database concept.

Initial scope:

- workflows;
- agents;
- runs;
- tasks;
- artifacts;
- receipts;
- standing orders;
- project rooms;
- tool grants;
- quality records.

## Phase 12 — aiagent.xyz

Ship worker marketplace with:

- manifests;
- packages;
- license/install rights;
- quality ledgers;
- install/run flow;
- worker receipts;
- contribution accounting.

## Phase 13 — sas.xyz

Ship outcome marketplace with:

- service listings;
- service orders;
- escrow/bond contracts;
- delivery bundles;
- provider/customer state;
- payout/dispute flow.

## Phase 14 — Runtime Node Scaling

Add:

- hosted nodes;
- DePIN mutual blind nodes;
- TEE enterprise secure nodes;
- customer VPC nodes;
- compute provider adapters.

## Dependency Rules

1. Persistent workers require wallet-core-lite.
2. My Agents requires minimal persistent agent state.
3. Marketplace workers require manifests, package refs, install/run flow, and receipts.
4. sas.xyz requires delivery bundles, escrow contracts, and provider runtime routing.
5. Agentgres v0 should be dogfooded before marketplace scale.
6. Marketplace neutrality/contribution accounting must exist before the default harness becomes too powerful.

## One-Line Doctrine

> **Build execution first, authority before autonomy, state before persistence, contribution accounting before marketplace scale.**
