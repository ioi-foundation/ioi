# Autopilot Local App and Workflow Canvas Specification

Status: canonical architecture authority.
Canonical owner: this file for Autopilot, workflow canvas, harness-as-workflow, and local GUI boundaries.
Supersedes: overlapping plan prose when Autopilot ownership conflicts.
Superseded by: none.
Last alignment pass: 2026-05-15.

## Canonical Definition

**Autopilot Desktop is the local canonical Web4 application and workbench for building, training, running, inspecting, and governing autonomous workflows and workers through a local IOI daemon/runtime profile.**

It is the default local execution environment for users who want private/local control, local files, local models, local connectors, and editable workflows.

## Core Role

Autopilot provides:

- workflow canvas;
- Autopilot Foundry / Worker Training Workbench;
- agent harness;
- local IOI daemon/runtime bridge management;
- local-first UX;
- connector/tool management;
- domain ontology, data recipe, and connector mapping authoring;
- model mounting and routing UI;
- training, evaluation, benchmark, and deployment UI;
- worker install/run interface;
- run rooms and task coordination;
- agent office/project coordination;
- artifact and receipt inspection;
- wallet.network approval surface;
- Agentgres client/runtime integration.

Autopilot may launch, configure, observe, and project the local daemon. It does
not define a second runtime substrate separate from the IOI daemon/domain
contracts.

## What Autopilot Owns

Autopilot owns the user-facing local product experience:

- workflow authoring;
- worker-training authoring;
- default harness inspection and fork path;
- local daemon/runtime configuration;
- local execution UX and debugging;
- local stores and projections;
- local/private files;
- local model endpoints;
- connector setup surfaces;
- domain ontology and canonical object model editors;
- data recipe and policy-bound data view builders;
- evaluation dataset builders;
- training profile selection;
- context graph and supersession editing;
- adapter, route-policy, and package promotion review;
- human approvals and interruption UX;
- run timeline;
- artifact viewer;
- diagnostics.

Autopilot owns the local user experience for Worker Training. It does not own
the canonical training state, receipt model, marketplace ranking, or runtime
execution substrate.

## What Autopilot Does Not Own

Autopilot does not own:

- the IOI daemon API contract;
- IOI L1 settlement contracts;
- global marketplace state;
- root user secrets except through wallet.network;
- first-party marketplace Agentgres domains;
- remote execution nodes;
- Filecoin/CAS payload availability;
- provider economics.

## Workflow Canvas

The workflow canvas is the construction language for bounded autonomous work.

It should support:

- triggers;
- model nodes;
- tool nodes;
- connector nodes;
- parser nodes;
- adapter nodes;
- decision nodes;
- loop/barrier nodes;
- human gates;
- output/materialization nodes;
- subgraphs;
- tests and fixtures;
- proposals;
- activation checklist;
- replay/debug panes.

## Harness-as-Workflow

The default agent harness should become a blessed workflow template.

Phases:

1. Render default harness as read-only graph.
2. Expose model/tool/verifier/approval/output slots.
3. Allow validated forks.
4. Allow proposal-only AI-authored workflow edits.
5. Package forked harnesses as worker/workflow manifests.

The default harness remains neutral infrastructure. It must not silently cannibalize marketplace workers.

## Autopilot Foundry

Autopilot Foundry is the local product surface for the Worker Training
lifecycle. It turns repeated work, examples, corrections, source documents,
quality gates, and verifier feedback into deployable workers.

Foundry should feel like a worker creation and improvement studio, not a
generic fine-tuning form. The primary UX is to help users create a better
worker faster: plan scope, capture or generate strong examples, gate weak
data, review efficiently, train or configure, compare, deploy, and improve
from failures when the worker returns for another pass.

The default guided flow is:

```text
Define Task
→ Select Base Model, Cognition Backend, or Training Profile
→ Bind Domain Ontology and Data Recipes
→ Plan Dataset Scope and Batch Strategy
→ Generate or Capture Raw Batches
→ Gate and Reject Weak Data
→ Human Review
→ Distill Ontology-Bound Data
→ Train or Configure
→ Evaluate
→ Package or Deploy as Worker
→ Monitor & Improve When Needed
```

Foundry is a lens over the shared Autopilot builder substrate, not a separate
canvas environment. Training recipes, evaluation recipes, benchmark recipes,
deployment recipes, data recipes, and outcome workflows should all be typed
recipes that can project into the standard workflow compositor.

The same Foundry flow should be openable as a workflow-compositor graph for
advanced inspection, customization, reuse, or composition. Canonical training
nodes include:

- task definition;
- domain schema;
- domain ontology builder;
- canonical object model editor;
- connector mapping;
- data recipe;
- policy-bound data view;
- source loader;
- training orchestrator;
- training copilot;
- batch planner;
- dataset workbench;
- raw batch archive;
- example generator;
- context graph editor;
- route-policy trainer;
- quality gate or judge;
- gate console;
- gate library;
- quality gate report;
- deduper or cleaner;
- PII / secrets filter;
- human review queue;
- model capacity advisor;
- model bake-off;
- cost/quality simulator;
- token and cost ledger;
- dataset exporter;
- distilled ontology dataset builder;
- evaluation dataset builder;
- ontology projection;
- trainer;
- evaluator;
- iteration loop;
- promotion gate;
- rollback gate;
- model registry or model mount;
- worker mount;
- deployment gate;
- deploy preview;
- worker card builder;
- feedback collector.

Foundry should support complementary views over the same recipe:

- **Guided View** for users who want a clear path from objective to trained
  worker.
- **Recipe View** for users who want to inspect stages, inputs, outputs,
  gates, costs, and candidate results without editing a graph.
- **Open in Workflow Composer** for builders who want to edit every planner,
  generator, gate, review, trainer, evaluator, deployment, and feedback node
  in the standard canvas.

The product should make the iteration loop visible. A failed eval, rejected
example, bad production output, or reviewer correction should become a concrete
next action: add an edge case, adjust a DataRecipe, tighten a gate, change a
rubric, generate more examples, try another training profile, compare against a
baseline, or update deployment thresholds.

The product should also make batch economics and batch quality visible. A
Training Orchestrator view should show the current batch plan, executor mix,
prompts, raw batch archive, gate pass/fail counts, rejection reasons, accepted
row yield, token burn, provider calls, cost per accepted row, and worklog. Raw
batches are inspectable evidence; only curated, gated, policy-authorized material
becomes training signal.

Foundry should expose a Model Capacity Advisor for small and efficient workers.
It should help builders decide whether the target should be a small local model,
adapter, retrieval/context worker, hosted model, or larger specialist based on
row structure, label complexity, prompt budget, tool count, latency, privacy,
cost, and eval risk. Smaller workers should receive tighter prompts, more
structured rows, smaller tool batches, and stronger gold-reason/eval coverage.

The user should be able to compare candidate workers before publication. A
Model Bake-Off view should run the same evaluation set against the base model,
candidate worker, previous worker version, frontier reference, competing
worker, or deterministic baseline, then show quality, cost, latency, and
failure categories.

The final product output should be a Worker Card, not merely a checkpoint file:
task class, ontology refs, data recipe refs, distilled dataset refs, evals,
benchmarks, known limitations, authority scopes, runtime profiles,
interaction surfaces, and deployment options.

Autopilot Foundry should expose training profiles rather than a single
fine-tuning path. Valid profiles include dense transformer workers,
MoE-backed workers, nonquadratic or subquadratic workers, hybrid
attention/state workers, retrieval-augmented/context-graph workers,
mutable-context workers, adapter-trained workers, distillation-trained workers,
perpetually post-trained workers, and deterministic verifier/toolchain workers.
Subquadratic or perpetually post-trained workers are supported classes, not the
Autopilot default or the protocol actor.

Autopilot can initiate training, evaluation, benchmark, and deployment jobs, but
those jobs run through daemon/domain contracts. Agentgres records training
specs, dataset commitments, lineage, receipts, benchmark state, and quality
records. wallet.network authorizes data, tool, model, and decryption access.
Filecoin/CAS stores large datasets, trace bundles, artifacts, checkpoints, and
sealed archives by hash/CID.

Autopilot Foundry should make the semantic data plane visible. Users should be
able to see which ontology, object model, connector mapping, data recipe,
policy-bound data view, evaluation dataset, and transformation receipts support
a worker. The product should not present raw uploads as if they were sufficient
domain truth.

CLI/TUI controls must be able to inspect and operate the same training runs,
quality gates, benchmark jobs, receipts, and routing decisions without creating
a separate terminal-only runtime truth path.

## Local vs Hosted Execution

Autopilot can execute locally or request external execution.

```text
Local:
  user machine, local files, local models, local connectors

Hosted:
  hosted IOI daemon/runtime node

DePIN:
  Akash-like or other compute node running an IOI daemon profile

Enterprise Secure:
  TEE-verified or customer VPC runtime node
```

Autopilot should choose placement according to policy, privacy, cost, latency, and user preference.

## Relationship to Marketplaces

Users may use Autopilot to:

- browse aiagent.xyz workers;
- install worker packages;
- order sas.xyz services;
- download packages from Filecoin/CAS/CDN;
- run workers locally;
- train workers locally or through runtime-node jobs;
- submit trained workers to aiagent.xyz categories;
- wrap worker-training templates as sas.xyz outcomes;
- monitor hosted runs;
- review delivery bundles;
- approve authority grants;
- inspect receipts.

Autopilot is not required for all marketplace users, but it is the best
local/private/power-user workbench over a local IOI daemon runtime.

## Local State

Autopilot should split state into:

### Ephemeral UI State

- selected tab;
- panel layout;
- hover/focus;
- modal state;
- unsaved form text;
- transient filters.

### Agentgres/Runtime State

- workflows;
- runs;
- tasks;
- artifacts;
- receipts;
- projections;
- local caches;
- mutation queues;
- worker installs;
- training specs;
- domain ontologies;
- canonical object models;
- data recipes;
- connector mappings;
- policy-bound data views;
- evaluation datasets;
- ontology projections;
- dataset commitments;
- training lineage;
- benchmark submissions;
- standing orders;
- project rooms;
- subscription cursors.

Autopilot may cache and render these records locally, but durable run, receipt,
artifact, patch, archive, and restore truth must flow through daemon and
Agentgres-compatible APIs.

## Invariants

1. Workflow UI must not create a second runtime truth path.
2. Every visible node must have honest runtime status.
3. The default harness is a neutral orchestrator/fallback, not a marketplace competitor.
4. Local execution should preserve user privacy by default.
5. wallet.network must authorize sensitive capabilities.
6. Agentgres must record durable run/receipt/artifact state where relevant.
7. Remote execution should be described as IOI daemon/runtime-node execution,
   not as an Autopilot-owned runtime.
8. Worker Training improves capability but does not grant authority.
9. Autopilot Foundry must not collapse MoW into a fine-tuning-only product.
10. Autopilot Foundry must not crown any single model architecture as the IOI
    default. Training profile claims must be evaluated, receipted, and
    rollback-capable before they affect deployment or routing.
11. Autopilot Foundry must bind training and evaluation to Domain Ontologies,
    DataRecipes, PolicyBoundDataViews, and transformation receipts whenever
    the work depends on governed domain data.

## One-Line Doctrine

> **Autopilot is where users operate Web4 locally: workflows become trained workers, local daemon execution stays inspectable, and sensitive authority remains governed.**
