# Autopilot Lifecycle Clarity Over IOI Primitives Master Guide

Owner: Autopilot / daemon-runtime / workflow-compositor / wallet.network / connectors-tools / Agentgres

Status: P0 lifecycle gate complete / regression guarded

Created: 2026-05-17

Primary audit input: `internal-docs/audits/autonomous-systems-shapes.md`

## Executive Doctrine

Autopilot should have ADK/Gemini-level lifecycle clarity over IOI's stronger
runtime primitives.

That means Autopilot must become easy to understand as a developer and product
lifecycle without weakening the IOI doctrine that makes it different:

- no second runtime;
- daemon/runtime contracts first;
- wallet.network authorizes power;
- Agentgres records operational truth;
- React Flow is an authoring/projection surface, not a truth store;
- models propose, runtime settles;
- tools and connectors are typed, permissioned, receipted capabilities;
- workflows compile into deterministic manifests;
- every live action has authority, policy, verification, and receipt posture;
- packageability, evaluation, replay, and deployment shape exist before
  connector sprawl.

The goal is not to copy Google ADK or Gemini Enterprise Agent Platform. The goal
is to absorb their clarity where they are strong:

- a clear thing a developer builds;
- a clear lifecycle from create to run to evaluate to deploy;
- a clear project/package topology;
- named session, state, memory, artifact, event, tool, and runner concepts;
- examples that teach canonical patterns rather than demos;
- evaluation and promotion as ordinary work, not special later work.

Then map that clarity onto IOI's primitives:

- Worker, Workflow, Harness, Capability, Policy, Authority, Receipt, Artifact,
  Event, Evaluation, DeploymentProfile, and PromotionDecision.

The named skeletal unit is:

> Autopilot's primary build artifact is an Autonomous System Package.

An Autonomous System Package is not an agent, connector, workflow, daemon
process, or policy bundle. It is the developer-facing package that binds worker
responsibility, workflow/harness topology, model/tool capabilities, authority,
memory/state/artifacts, evals, deployment profiles, and receipts. Internally it
may compile to, or profile, `ManifestEnvelope`; product/doctrine-wise it is
first-class.

This was the P0 gate before broad Phase 5 connector expansion. Phase 5
Workstream 1 filesystem/Git proposal-first mutation now exists as the canonical
proof sample for this lifecycle shape.

## Decision

Before connector breadth, lock the lifecycle shape. That gate is now complete.

Phase 5 should be staged as:

```text
P0 lifecycle clarity hardening
-> canonical local proof sample
-> filesystem/Git proposal-first workstream
-> browser/computer-use hardening
-> local shell/sandbox hardening
-> local creative/CAD connectors
-> read-only/draft-only production SaaS connectors
```

Broad Phase 5 connector expansion may now proceed from the package/readiness
shape proved here. Production connector lanes should copy the lifecycle package
shape instead of becoming bespoke teaching patterns.

## North Star

Autopilot is a sovereign autonomous-systems workbench where a developer can
create, inspect, run, evaluate, package, deploy, and improve an autonomous
system through one comprehensible lifecycle, backed by IOI runtime truth.

The developer-facing mental model should be:

```text
Autonomous System Package
  identity and responsibility
  workflow or harness topology
  model capabilities
  tool and connector capabilities
  skills and instructions
  authority and policy profile
  session/state/memory/artifact profile
  evaluation profile
  runtime/deployment profiles
  receipts, traces, replay, and promotion status
```

The runtime truth underneath should remain:

```text
ManifestEnvelope / AutonomousSystemManifest profile
WorkerInstanceEnvelope
WorkflowManifest
RuntimeToolContract
ModelCapability
AuthorityScopeRequestEnvelope
AuthorityGrantEnvelope
RunEnvelope
RuntimeEventEnvelope
ReceiptEnvelope
ArtifactEnvelope
EvaluationDatasetEnvelope
QualityGateReportEnvelope
PromotionDecisionEnvelope
```

## Non-Negotiables

1. Do not introduce a framework-owned agent runtime.
2. Do not make React Flow source of truth.
3. Do not make examples bypass wallet authority, policy, receipts, or
   capability readiness for convenience.
4. Do not let provider names such as OpenAI, Gemini, Claude, Playwright, Gmail,
   GitHub, Blender, or FreeCAD become workflow semantics.
5. Do not treat callbacks/hooks as ungoverned side-effect code.
6. Do not collapse policy into tracing or observability.
7. Do not add connector-specific UX until the generic lifecycle slot exists.
8. Do not make cloud deployment the default mental model.
9. Do not bury sessions, state, memory, artifacts, evals, or promotion in
   advanced internals.
10. Do not proceed to broad connector expansion without a package/readiness
    lens.

## Completion Dashboard

| Row | Target | Status | Done When |
| --- | --- | --- | --- |
| P0-1 | Autonomous System Package shape | Done / regression guarded | Product/doctrine asserts the first-class build artifact; manifest/profile contract binds worker, workflow, harness, capabilities, authority, memory/state/artifacts, eval, runtime/deployment, promotion, marketplace/foundry metadata. |
| P0-2 | Canonical lifecycle glossary | Done / regression guarded | Agent/Worker/Skill/Tool/Connector/Workflow/Harness/Capability/Policy/Trace/Receipt/Runtime terms have stable definitions and product-label mappings. |
| P0-3 | Lifecycle verb loop | Done / regression guarded | Compose, bind, simulate, authorize, run, verify, inspect receipts, package, deploy, promote, improve are documented and projected into Autopilot/CLI/SDK surfaces. |
| P0-4 | Canonical proof sample | Done / regression guarded | A repo-maintenance autonomous system sample demonstrates local fs/Git proposal-first mutation with authority, approvals, evals, receipts, and GUI run checklist. |
| P0-5 | Workflow package readiness | Done / regression guarded | Workflow Composer shows run readiness separately from autonomous-system package readiness and promotion readiness. |
| P0-6 | Lifecycle APIs and projections | Done / regression guarded | Daemon/API/SDK/CLI/TUI/Autopilot can expose lifecycle status without duplicating runtime truth. |
| P0-7 | Evaluation as default | Done / regression guarded | The proof sample and Phase 5 entry lanes ship fixture evals, scorecards, replay expectations, and promotion gates. |
| P0-8 | Migration compatibility | Done / regression guarded | Existing workflows project deterministically into the package/lifecycle lens without breaking stored graphs. |
| P0-9 | Documentation convergence | Done / regression guarded | Phase 5 and workflow/computer-use plans reference this guide as the P0 lifecycle gate and no longer imply connector breadth is the immediate target. |

## Completion Record

Completed on 2026-05-17.

Implementation landed in slice commits that:

- canonized Autonomous System Package, `AutonomousSystemManifest` profile, and
  lifecycle terminology in architecture docs;
- added deterministic lifecycle readiness projection and package manifest
  projection helpers for old and new workflows;
- exposed lifecycle readiness in Workflow Composer, SDK JSON helpers, and
  `ioi agent lifecycle --json`;
- added the repo-maintenance Autonomous System Package proof sample with
  workflow, model/tool capability bindings, authority policy, approval profile,
  eval cases, expected receipts, fixture repo, GUI checklist, and run
  instructions;
- validated the proof sample through the live Autopilot Workflow Composer GUI
  with proposal-first fs/Git posture, approval interruptions, fixture replay,
  package export, and readiness evidence.

Generated GUI evidence for the final proof run was written outside git under:

```text
/tmp/autopilot-lifecycle-proof/2026-05-17T10-05-11Z
```

## What "Lifecycle Clarity" Means

Lifecycle clarity means a developer can answer these questions without reading
six architecture files:

- What am I building?
- What files or manifests define it?
- What authority does it need?
- What can it run locally without grants?
- What changes when it goes live?
- How do I test it?
- How do I see what happened?
- How do I package it?
- How do I deploy it?
- How do I promote or reject it?
- How do I replay it later?
- How do I make it marketplace- or Foundry-compatible later?

IOI can keep a sophisticated internal architecture, but the operator-facing
shape must feel inevitable and teachable.

## ADK/Gemini Clarity To Absorb

### Clear Build Object

ADK and Gemini-style platforms make the developer feel there is a specific
thing being built: an agent, app, or deployable runtime object.

Autopilot should expose:

```text
Autonomous System Package
```

as the developer-facing build artifact. The implementation can represent it as
`AutonomousSystemManifest`, a strict `ManifestEnvelope` profile, or both. That
is an implementation decision; the product/doctrine concept is not optional.

### Clear Project Topology

ADK samples and Agents CLI-style projects teach a project shape:

```text
README
agent or worker definition
tools
callbacks/hooks
evals
tests
deployment config
environment setup
```

Autopilot should teach:

```text
README
system manifest
workflow manifest
harness profile
tool contracts
model capability refs
authority policy
approval profile
session/state/memory/artifact profile
eval cases
receipt expectations
runtime/deployment profile
promotion status
```

### Clear Lifecycle Verbs

ADK/Gemini clarity comes from obvious verbs:

- create;
- configure;
- run;
- inspect;
- evaluate;
- deploy;
- monitor;
- optimize.

Autopilot should use one explicit loop:

```text
compose -> bind -> simulate -> authorize -> run -> verify -> inspect receipts
-> package -> deploy -> promote -> improve
```

Short form for product surfaces:

```text
build -> bind authority -> test -> run -> inspect receipts -> package
-> promote
```

### Clear Named Runtime Concepts

ADK makes concepts such as session, state, memory, artifact, event, tool, and
runner easy to name. IOI should expose equally clear names, while preserving
Agentgres, wallet, daemon, and receipt truth behind them.

### Examples As Canon

ADK samples teach how a system should be assembled. IOI examples must be
production-shaped, not toy-shaped:

- safe by default;
- explicit authority;
- fixture/live posture visible;
- receipts and artifacts expected;
- eval cases included;
- GUI and CLI instructions aligned;
- package/promotion status visible.

## IOI Primitives To Preserve

### Worker

Durable actor, responsibility boundary, package identity, routing target, and
event/receipt subject.

### Agent

Product-facing instance or compatibility alias. It may refer to a worker-backed
runtime, but it is not the low-level protocol actor.

### Workflow

Deterministic composition manifest. React Flow authors and projects it, but the
runtime executes the daemon/workflow manifest.

### Harness

Reusable workflow topology for a behavior class, such as coding loop,
browser/computer-use loop, evaluation loop, or proposal-first mutation loop.

### Capability

Primitive or model/tool capability reference. Capability describes feasibility
and contract shape, not authority.

### Authority

wallet.network grant or lease over resource, provider, identity, budget,
approval, secret, and expiry.

### Policy

Admission and behavior rules over authority, risk, approval, privacy,
retention, evidence, and execution posture.

### Tool

Executable capability with input schema, output schema, risk class, primitive
capabilities, authority scopes, approval requirements, and receipt behavior.

### Connector

External system adapter exposing tools. It is not ambient authority and does
not own runtime truth.

### Skill

Instruction/resource/procedure package. It can influence prompts and context,
but it does not execute work or grant authority by itself.

### Session, State, Memory, Artifact

Developer-facing lifecycle names for runtime and Agentgres-backed records:

- Session: current interaction/run context.
- State: scoped serializable working data.
- Memory: governed long-term recall or retrieval surface.
- Artifact: materialized output, evidence, or deliverable.

### Event, Trace, Receipt

- Event: observation that something happened.
- Trace: ordered diagnostic/observability path through runtime behavior.
- Receipt: durable proof of an action, decision, verification, artifact,
  authority use, or promotion outcome.

## Target Developer Lifecycle

The canonical lifecycle loop is:

```text
compose -> bind -> simulate -> authorize -> run -> verify -> inspect receipts
-> package -> deploy -> promote -> improve
```

### 1. Compose

The user composes an Autonomous System Package from:

- a template;
- a blank workflow;
- an imported workflow;
- a sample;
- a package/manifest;
- an existing worker.

Output:

- draft Autonomous System Package;
- draft autonomous-system manifest/profile;
- workflow/harness reference;
- initial capability requirements;
- package readiness status.

### 2. Bind

The user binds:

- model capabilities;
- tool capabilities;
- connector capabilities;
- skills;
- memory profile;
- artifact retention;
- authority scopes;
- approval profile;
- eval profile;
- runtime/deployment profile.

Output:

- deterministic manifest projection;
- readiness report;
- missing-grant report;
- mock/live posture.

### 3. Simulate

The user runs fixture, dry-run, or mocked paths before live authority is used.

Output:

- simulated run result;
- fixture events;
- proposal previews;
- readiness blockers;
- expected receipt plan;
- eval compatibility signal.

### 4. Authorize

The user or policy grants the package the authority it needs for the selected
runtime profile.

Output:

- authority scope request;
- grant or denial;
- approval requirements;
- secret/BYOK lease posture;
- fail-closed live-action status.

### 5. Run

The system runs through daemon/runtime APIs.

Output:

- run id;
- event stream;
- trace view;
- receipts;
- artifacts;
- verification state.

### 6. Verify

The runtime verifies that material actions produced the expected state changes.

Output:

- verification receipt;
- postcondition status;
- failure category;
- recovery recommendation;
- replay anchor.

### 7. Inspect Receipts

The user sees:

- topology;
- current step;
- model/tool proposals;
- policy decisions;
- approvals;
- action receipts;
- artifacts;
- failure/recovery state.

This must be glass-box without turning tracing into policy.

### 8. Evaluate

The user runs fixture or live evals:

- expected behavior;
- regression cases;
- simulated users/environments;
- scorecard rows;
- failure taxonomy;
- replay bundle.

Output:

- quality gate report;
- promotion eligibility;
- regression guard.

### 9. Package

The user packages the system when:

- manifest is complete;
- capabilities are bound;
- authority requirements are explicit;
- eval profile exists;
- receipts/artifact behavior is defined;
- deployment profile slots are present.

Output:

- package manifest/profile;
- package readiness receipt;
- optional Worker Card preview.

### 10. Deploy

Deployment profiles may include:

- local daemon;
- task-scoped browser profile;
- local container;
- local VM;
- hosted daemon;
- cloud container;
- cloud VM;
- customer VPC;
- TEE;
- DePIN;
- mobile/device provider.

In this P0 guide, the slot matters more than full implementation.

### 11. Promote

Promotion means the package becomes eligible for:

- internal reuse;
- scheduled/background use;
- marketplace exposure;
- service composition;
- Foundry/eval/training feedback.

Output:

- PromotionDecisionEnvelope or profile;
- quality gate report;
- known limitations;
- authority posture;
- eval scorecard.

### 12. Improve

The system improves through:

- trajectory review;
- failure taxonomy;
- prompt/skill changes;
- tool contract changes;
- eval additions;
- workflow/harness revision;
- policy changes;
- Foundry-compatible data recipes later.

## Autonomous System Package And Manifest Target

Autopilot's primary build artifact is an Autonomous System Package.

The package is the product and developer concept. The manifest is the runtime
contract/profile that makes the package deterministic, portable, evaluable, and
receipted.

This guide does not require a brand-new runtime substrate. The first
implementation can be a strict profile over existing `ManifestEnvelope` and
workflow manifest objects. That implementation choice must not make the package
concept psychologically invisible to users.

Working name:

```text
AutonomousSystemManifest
```

Minimum shape:

```yaml
system_id: ai://...
display_name: string
description: string
version: semver_or_hash
status: draft | runnable | package_ready | deployable | promoted | revoked

worker:
  worker_ref: worker://... | agent://...
  responsibility: string
  owner_ref: ioi://publisher/...

workflow:
  workflow_manifest_ref: artifact://... | cid://... | inline_ref
  harness_ref: optional
  topology_hash: string

capabilities:
  model_capability_refs: []
  tool_capability_refs: []
  connector_refs: []
  primitive_capabilities_required: []

authority:
  authority_scope_requirements: []
  grant_requirements: []
  approval_profile_ref: optional
  policy_profile_ref: optional
  revocation_posture: fail_closed | pause | degrade_read_only

runtime_profiles:
  - profile_id: profile://...
    kind: local_daemon | task_browser | local_container | hosted_daemon | cloud_vm | tee | depin | customer_vpc
    readiness: ready | degraded | missing | external
    cleanup_policy_ref: optional

session_state_memory_artifacts:
  session_profile_ref: optional
  state_profile_ref: optional
  memory_profile_ref: optional
  artifact_retention_profile_ref: optional
  observation_retention_mode: summary_only | local_redacted | local_raw | encrypted_local_raw | no_persistence

evaluation:
  eval_profile_refs: []
  benchmark_refs: []
  quality_gate_refs: []
  replay_profile_ref: optional

promotion:
  promotion_profile_ref: optional
  marketplace_exposure_eligibility: none | internal | review_required | eligible
  foundry_lineage_refs: []
  worker_card_preview_ref: optional

receipts:
  package_readiness_receipt_ref: optional
  latest_run_receipt_refs: []
  latest_eval_receipt_refs: []
```

## Lifecycle Readiness Model

Autopilot should distinguish these readiness types:

| Readiness | Meaning | Blocking Scope |
| --- | --- | --- |
| Run readiness | Can this graph execute now in the selected runtime profile? | Blocks Run. |
| Authority readiness | Are required grants, approvals, and secret leases available? | Blocks live effects. |
| Package readiness | Is this a complete autonomous-system package? | Blocks package/publish. |
| Evaluation readiness | Are eval cases and quality gates defined? | Blocks promotion. |
| Deployment readiness | Can this target runtime profile run the package? | Blocks deploy. |
| Promotion readiness | Is this safe/qualified for reuse, marketplace, service, or Foundry loops? | Blocks promotion. |

The UI must not collapse these into one vague "ready" indicator.

## Required Product Surfaces

### Autopilot Home

Should show autonomous systems as first-class objects:

- drafts;
- runnable systems;
- package-ready systems;
- deployed systems;
- blocked systems;
- recent receipts;
- eval status.

### Workflow Composer

Should show:

- run readiness;
- package readiness;
- missing lifecycle slots;
- capability bindings;
- authority requirements;
- eval profile;
- artifact/receipt behavior;
- promotion blockers.

React Flow remains projection. Every displayed status should map back to daemon,
wallet, Agentgres, manifest, or receipt truth.

### Inspector

Inspector tabs should be lifecycle-oriented:

- Configure;
- Capabilities;
- Authority;
- Policy;
- Memory/State/Artifacts;
- Evaluation;
- Runtime/Deployment;
- Receipts/Trace;
- Advanced.

### Run History / Trace

Should show:

- lifecycle stage;
- active workflow node;
- model/tool proposal;
- policy decision;
- authority grant or missing grant;
- approval decision;
- receipt id;
- artifact refs;
- verification state.

### Authority Center

Should show grants and policies in lifecycle terms:

- what this system wants;
- why it wants it;
- what profile it belongs to;
- what grants are live;
- what approvals are pending;
- what receipts will be emitted.

### CLI / TUI

Minimum commands or equivalent:

```text
ioi system create
ioi system inspect
ioi system readiness
ioi system run
ioi system eval
ioi system package
ioi system deploy --profile local
ioi system receipts
```

Existing `workflow`, `agent`, and `tool` commands may remain, but they should
project into this lifecycle language when appropriate.

### SDK

Minimum developer shape:

```text
defineSystem(...)
bindModelCapability(...)
bindToolCapability(...)
requireAuthorityScope(...)
defineEvalProfile(...)
runSystem(...)
inspectReadiness(...)
packageSystem(...)
```

This can be a wrapper over existing SDK clients. It should not duplicate daemon
truth.

## Canonical Proof Sample

Working name:

```text
repo-maintenance-autonomous-system
```

Purpose:

Prove Phase 5 Workstream 1 as a lifecycle-shaped autonomous system, not just a
set of filesystem/Git tools.

The sample should include:

- README;
- autonomous system manifest/profile;
- workflow manifest;
- harness profile;
- model capability binding;
- filesystem and Git tool capability bindings;
- authority policy;
- approval profile;
- fixture repository;
- eval cases;
- expected run trace;
- expected receipts;
- GUI workflow checklist;
- CLI/TUI run instructions;
- package readiness checklist;
- known limitations.

Example task:

```text
Inspect a repository, identify one safe documentation typo or formatting issue,
propose a patch, show the diff, request approval, apply the patch, run a
targeted validation command, emit receipts, and record package/eval status.
```

Required proof:

- no ambient workspace write;
- proposal-first mutation;
- approval-gated apply;
- idempotency or replay policy;
- rollback/restore artifact when mutation occurs;
- receipt for proposal, approval, apply, validation, and artifact;
- run history visible in Autopilot;
- old workflow compatibility preserved.

## Implementation Workstreams

### Workstream A: Contract And Docs Lock

Goal: make the package/lifecycle shape canonical enough to implement.

Tasks:

1. Add lifecycle clarity row to source-of-truth map.
2. Assert Autonomous System Package as the primary build artifact.
3. Define `AutonomousSystemManifest` as the manifest/profile contract for that
   package, either as a strict `ManifestEnvelope` profile or a separate envelope
   if implementation needs prove it.
4. Publish glossary/boundary table.
5. Update Phase 5 guide to reference this P0 gate.
6. Update workflow compositor docs to use lifecycle language.

Acceptance:

- docs name one package concept;
- no conflict with existing Worker/Workflow/Manifest definitions;
- Phase 5 no longer reads as connector breadth first.

### Workstream B: Readiness Engine

Goal: turn lifecycle clarity into a deterministic readiness projection.

Tasks:

1. Define readiness categories and status enums.
2. Add projection helper from workflow/capability/authority/eval data to
   lifecycle readiness.
3. Preserve old workflow compatibility.
4. Add tests for missing model capability, missing authority, missing eval,
   missing deployment profile, and package-ready state.

Acceptance:

- run readiness and package readiness are distinct;
- live effects fail closed;
- package blockers are specific and actionable.

### Workstream C: Workflow Composer UX

Goal: make lifecycle status visible where systems are authored.

Tasks:

1. Add package readiness panel or summary to composer.
2. Add lifecycle inspector sections.
3. Surface capability, authority, eval, artifact, receipt, and deployment slots.
4. Keep raw runtime/advanced details accessible.
5. Add GUI probe for creating/loading the proof sample and checking readiness.

Acceptance:

- user can see why a workflow can run but cannot yet package/promote;
- advanced runtime truth remains inspectable;
- no React Flow shadow truth introduced.

### Workstream D: Canonical Proof Sample

Goal: create the first lifecycle-shaped example.

Tasks:

1. Add sample directory.
2. Add manifest/profile fixtures.
3. Add workflow/harness fixture.
4. Add fs/Git tool capability fixture bindings.
5. Add eval cases and expected receipts.
6. Add README and GUI checklist.
7. Add regression tests.

Acceptance:

- the sample can be run locally in fixture mode;
- the sample teaches the correct lifecycle shape;
- future connector lanes can copy the package structure.

### Workstream E: CLI/TUI/SDK Projection

Goal: make lifecycle language available outside the GUI.

Tasks:

1. Add or project `system readiness` output.
2. Add JSON output for package readiness.
3. Add SDK helper types or examples.
4. Add TUI lifecycle summary rows where existing run/workflow screens allow.

Acceptance:

- lifecycle status is not GUI-only;
- JSON output can drive tests and docs.

### Workstream F: Evaluation And Promotion Gate

Goal: make evals ordinary for Phase 5.

Tasks:

1. Define minimal eval profile for proof sample.
2. Add scorecard output.
3. Add promotion readiness blocker until eval profile exists.
4. Add replay/receipt expectations.

Acceptance:

- package readiness may pass without promotion readiness;
- promotion readiness requires eval evidence.

## Slice Order

1. Create/commit this guide and update Phase 5 status.
2. Add canonical terminology and manifest/profile docs.
3. Implement readiness projection in runtime/workflow helpers.
4. Add Workflow Composer readiness UI.
5. Add proof sample fixture.
6. Add CLI/SDK JSON readiness projection.
7. Add GUI and regression validation.
8. Only then resume broader Phase 5 connector lanes.

## Validation Plan

### Static Docs Validation

Commands:

```text
git diff --check
run a placeholder-marker scan across internal-docs/plans and docs/architecture
```

### Unit/Static Tests

Target tests should cover:

- manifest/profile projection;
- old workflow compatibility;
- readiness category computation;
- fail-closed live run gating;
- eval/promotion readiness blockers.

### GUI Validation

Use Playwright/autopilot harness to confirm:

- user can open Workflow Composer;
- proof sample is discoverable;
- run readiness appears;
- package readiness appears;
- missing authority/eval/deployment blockers are legible;
- raw runtime details remain in advanced/receipts surfaces;
- blank or invalid graph fails closed.

### CLI/TUI Validation

Confirm:

- lifecycle readiness JSON output;
- readable TUI lifecycle summary;
- commands do not require provider credentials in fixture mode.

## Definition Of Done

This P0 leg is complete when:

- Autonomous System Package is asserted as the first-class build artifact;
- `AutonomousSystemManifest` or equivalent package profile is documented as
  the contract/profile for that package;
- terminology boundaries are canonical;
- lifecycle verbs are documented and visible in at least one product surface;
- Workflow Composer distinguishes run, authority, package, evaluation,
  deployment, and promotion readiness;
- canonical repo-maintenance proof sample exists;
- proof sample has fixture evals and expected receipts;
- CLI/SDK JSON can expose lifecycle readiness;
- old workflows remain compatible;
- tests and GUI probe pass;
- Phase 5 guide points to this lifecycle gate;
- broad connector lanes are allowed to proceed only after these rows are Done
  or explicitly deferred.

## Explicit Deferrals

These are not required before Phase 5 Workstream 1:

- full cloud deployment platform;
- hosted worker marketplace;
- Foundry training/post-training pipeline;
- real Google Workspace live credentials;
- production Blender/FreeCAD connectors;
- mobile device providers;
- paid service marketplace publication;
- public consumer docs.

These are required as slots, not full implementations:

- deployment profiles;
- promotion profile;
- marketplace eligibility;
- Foundry lineage;
- eval profile;
- artifact retention;
- runtime profile readiness.

## Risks If Ignored

If connector expansion proceeds before lifecycle clarity:

- every connector becomes a bespoke product surface;
- Workflow Composer becomes a capability picker rather than an autonomous
  system builder;
- policy and authority UX will feel disconnected from workflows;
- examples will teach shortcuts around IOI doctrine;
- marketplace and Foundry packaging will require retroactive migration;
- deployment semantics will be invented per integration;
- users will understand tools but not systems;
- Phase 5 will add surface area without increasing architectural legibility.

## Current Next Tactical Slice

The P0 lifecycle clarity gate is complete. The next tactical slice belongs to
Phase 5:

1. Start filesystem/Git proposal-first mutation as the first production-grade
   connector lane.
2. Reuse the repo-maintenance Autonomous System Package structure as the
   canonical package/readiness/eval/receipt shape.
3. Keep broad connector expansion behind capability contracts, wallet authority,
   policy admission, proposal-first mutation where applicable, verification,
   and receipts.
