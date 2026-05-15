# Implementation Roadmap and Dependency Specification

Status: canonical architecture roadmap.
Canonical owner: this file for high-level implementation sequencing; low-level proof gates live in [`low-level-implementation-milestones.md`](./low-level-implementation-milestones.md).
Supersedes: overlapping roadmap prose when phase ordering conflicts.
Superseded by: none.
Last alignment pass: 2026-05-15.

## Purpose

This roadmap orders implementation so product surfaces ship without violating architectural boundaries.

## Strategic Order

```text
Workflow Canvas V1 Hardening
→ Workflow Runtime Parity
→ Harness Componentization
→ Harness-as-Workflow
→ Phase 4.5 Capability Authority Readiness Gate
→ Phase 5 Early Connector Expansion
→ Autopilot Foundry / Worker Training Workbench
→ Minimal Persistent Worker/Agent State
→ Daemon-backed CLI/TUI Operator Controls
→ My Agents GUI
→ Worker Office / Project Rooms
→ Worker/Agent API
→ Agentgres v0
→ aiagent.xyz Worker Marketplace
→ Sparse Worker Categories / MoW Router
→ sas.xyz Service Marketplace
→ Worker Training as Service-as-Software
→ Marketplace Neutrality / Contribution Accounting hardening
→ Receipt-Weighted Credit Settlement
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

## Phase 4.5 — Capability Authority Readiness Gate

Goal: remove remaining authority drift before Phase 5 connector expansion.

Build:

- canonical connector/tool/model capability registry metadata;
- wallet-core-lite authority path for BYOK, connector secrets, grants, approval tokens, revocation, and audit receipts;
- capability request APIs so workflows call model/tool capabilities rather than provider-specific branches;
- Autopilot Policy/Settings authority center refresh for credentials, grants, approvals, and stale settings removal;
- React Flow capability binding/readiness projections;
- Playwright-backed browser/computer-use readiness probes for isolated task contexts and degraded/fail-closed paths;
- go/no-go report proving Phase 5 can start without a second runtime or shadow truth store.

Authoritative guides:

- [Phase 4.5 Capability Authority Readiness Master Guide](../plans/phase-4-5-capability-authority-readiness-master-guide.md)
- [Isolated Computer Providers Master Guide](../plans/isolated-computer-providers-master-guide.md)

## Phase 5 — Early Connector Expansion

Goal: prove Autopilot can operate real production software safely without
starting with money-moving commerce.

Build:

- filesystem and Git read/write with proposal-first mutation;
- browser/computer-use hardening;
- local shell/sandbox hardening;
- Blender connector;
- FreeCAD/CAD connector;
- read-only Google Workspace and mail improvements;
- draft-only email/calendar/doc outputs.

Authoritative guide:

- [Phase 5 Early Connector Expansion Master Guide](../plans/phase-5-early-connector-expansion-master-guide.md)

## Phase 6 — Minimal Persistent Workers And My Agents

Goal: add durable workers only after Phase 4.5 authority and Phase 5 connector
proofs are working.

Build:

- background worker records;
- task/job lifecycle APIs;
- schedule monitors;
- worker pause/resume/cancel;
- hosted worker fail-closed records;
- worker receipts and dashboards;
- My Agents surfaces backed by runtime contracts.

## Phase 6.5 — Autopilot Foundry / Worker Training Workbench

Goal: turn repeated workflows, examples, corrections, source material, and
verifier gates into deployable workers without creating a private training
runtime.

Build:

- Train a Specialist wizard;
- editable training workflow graph;
- domain ontology and canonical object model authoring;
- data recipe and connector mapping builders;
- policy-bound data view selection;
- transformation run and receipt inspection;
- evaluation dataset builder;
- ontology-aware Agentgres projection previews;
- training spec and dataset commitment projections;
- quality gate and human review queues;
- train/configure/evaluate controls over daemon APIs;
- TrainingReceipt, EvaluationReceipt, and BenchmarkReceipt inspection;
- CLI/TUI controls for training runs, benchmark jobs, and receipt review.

Exit:

- users can turn a recurring local workflow into a policy-bound WorkerManifest
  with training lineage and an evaluation report.

## Phase 7 — Minimal Persistent Worker/Agent State

Goal: product-facing agents become protocol workers, not personas.

Objects:

- `WorkerDefinition`;
- `WorkerInstall`;
- `WorkerRun`;
- `AgentDefinition`;
- `AgentInstall`;
- `AgentRun`;
- `AgentToolGrant`;
- `AgentSchedule`;
- `StandingOrder`;
- `AgentInboxItem`;
- `AgentArtifact`;
- `AgentReceipt`.

## Phase 7.5 — Daemon-backed CLI/TUI Operator Controls

Goal: the terminal/TUI operator surface can control the same daemon substrate as
SDK, agent-ide, Autopilot, harnesses, and benchmarks.

Surfaces:

- thread and turn lifecycle;
- interrupt and steering controls;
- approvals and policy decisions;
- model, thinking, usage, context budget, and compaction controls;
- memory and MCP manager controls;
- subagent lifecycle controls;
- snapshots, restore preview/apply, diagnostics repair, and jobs;
- event streaming and receipt inspection.

Exit:

- no TUI-only runtime state transition exists without a daemon/domain API route.

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

## Phase 9 — Worker Office / Project Rooms

Goal: long-duration planner/worker coordination.

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

## Phase 10 — Worker/Agent API

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
- Sparse Worker Categories;
- benchmark profiles;
- routing eligibility;
- training lineage refs;
- license/install rights;
- quality ledgers;
- install/run flow;
- worker receipts;
- contribution accounting.

## Phase 12.5 — Sparse Worker Categories / MoW Router

Ship worker category and routing infrastructure with:

- category profiles and evaluation rubrics;
- benchmark submissions and receipts;
- candidate-set commitments;
- routing decision receipts;
- worker ranking by benchmark, policy, cost, trust, and contribution evidence;
- no hidden first-party substitution.

## Phase 13 — sas.xyz

Ship outcome marketplace with:

- service listings;
- service orders;
- escrow/bond contracts;
- delivery bundles;
- provider/customer state;
- payout/dispute flow.

## Phase 13.5 — Worker Training as Service-as-Software

Ship the first MoW-native service wedge:

- Worker Training listing type;
- training contract and acceptance rubric;
- training-data handling policy;
- evaluation and benchmark deliverables;
- trained worker package delivery;
- optional aiagent.xyz publication;
- deterministic dispute path for failed training outcomes.

## Phase 14 — Marketplace Neutrality / Receipt-Weighted Settlement

Harden the MoW economy with:

- contribution roots;
- reward roots;
- routing decision roots;
- receipt-weighted subscription credit distribution;
- royalties for worker authors and upstream contributors;
- dispute penalties and no-fault statuses.

## Phase 15 — Runtime Node Scaling

Add:

- hosted nodes;
- DePIN mutual blind nodes;
- TEE enterprise secure nodes;
- customer VPC nodes;
- compute provider adapters.

## Dependency Rules

1. Persistent workers require wallet-core-lite.
2. My Agents requires minimal persistent worker/agent state.
3. Marketplace workers require manifests, package refs, install/run flow, and receipts.
4. Autopilot Foundry requires workflow runtime parity, model routing, wallet authority, Domain Ontology/DataRecipe objects, daemon training endpoints, and Agentgres receipt state.
5. Sparse Worker Categories require WorkerManifest MoW fields, benchmark receipts, quality records, and routing decision receipts.
6. sas.xyz requires delivery bundles, escrow contracts, Worker Training contract objects, and provider runtime routing.
7. Agentgres v0 should be dogfooded before marketplace scale.
8. Marketplace neutrality/contribution accounting must exist before the default harness becomes too powerful.

## One-Line Doctrine

> **Build execution first, authority before autonomy, worker training before marketplace liquidity, state before persistence, and contribution accounting before marketplace scale.**
