# Workflow Compositor Primitive Taxonomy & UX Master Guide

Status: source-of-truth guide for the next workflow compositor sprint
Created: 2026-05-14
Inputs:

- `docs/audits/agent-workflow-compositor-primitive-taxonomy-ux-audit.md`
- `docs/audits/agent-workflow-compositor-live-clickthrough-ux-audit.md`

## Purpose

This guide turns the static taxonomy audit and live GUI clickthrough audit into
one implementation plan for the Workflow Compositor. The goal is not visual
polish. The goal is a clearer authoring language for composing IOI-backed
agents, workflows, workers, policies, tools, memory, skills, verification, and
outcomes.

The compositor should feel like a small, durable set of generic workflow
primitives. Runtime complexity should remain available through typed config,
ports, inspectors, receipts, and advanced/debug surfaces.

## Doctrine

Non-negotiables:

- No second runtime.
- No React Flow shadow truth store.
- Daemon/runtime contracts first.
- React Flow is a configurable authoring/projection surface, not runtime state.
- Every user-facing primitive maps to a canonical runtime component, adapter,
  policy, event, receipt, artifact, or manifest.
- Every config field compiles to a deterministic workflow/runtime manifest.
- Graph activation produces deterministic ids, receipts, and replayable state.
- Advanced/runtime surfaces must preserve every low-level contract even when the
  default palette hides implementation facets.

## Problem Statement

The compositor is runtime-complete but authoring-heavy. The current palette
exposes too many implementation facets as first-class choices:

- skill discovery, pinned skills, skills, and skill packs;
- memory search/list/policy/remember/edit/delete/status;
- subagent lifecycle actions under State instead of a Worker concept;
- model binding/model call/parser as separate authoring concepts;
- GitHub/repository/issue/PR fragments instead of a repo/PR flow;
- runtime task/job/checklist/package/projection rows in the default palette;
- composition helpers that are visible but not searchable;
- broad search matches that drown intent, such as `pr` returning 52 primitives;
- a blank-composer `Run` path that can route to a Chat render-blocked failure.

The next leg should simplify authoring without weakening runtime proof.

## Target State

The default composer presents a small palette of canonical primitives, each with
clear execution semantics. Specialized behavior is expressed as:

- typed configuration modes;
- default ports and compatible-next suggestions;
- policy and authority sections;
- inspector tabs for evidence, receipts, manifests, runtime ids, and debug data;
- advanced palette entries for protocol/debug users.

Target sentence:

> The workflow compositor exposes a small set of generic, composable
> agent-runtime primitives that can be configured to build any worker, harness,
> or outcome workflow. Specialized behavior appears as typed configuration,
> ports, policies, inspectors, emitted events, and receipts unless it represents
> a distinct execution boundary.

## Completion Dashboard

| Priority | Area | Target state | Status |
| --- | --- | --- | --- |
| P0 | Blank composer Run safety | Invalid or blank workflows fail closed in the composer with validation/readiness evidence; no Chat render-blocked page. | Done / regression guarded |
| P0 | Canonical taxonomy metadata | Every node definition and creator preset has canonical primitive metadata, palette visibility, collapse target, search aliases, and runtime mapping. | Planned |
| P0 | Default vs advanced palette | Default palette shows authoring primitives/templates; advanced palette exposes raw runtime/protocol/debug nodes. | Planned |
| P1 | Search and synonyms | Common authoring words find the expected primitive: worker, terminal, agent, pull request, repo, skills, memory, tool, policy. | Planned |
| P1 | Primitive collapse | Skills, Memory, Tool Pack, Worker, Repository/Pull Request, Hook, Model/Agent Step collapse into config modes where appropriate. | Planned |
| P1 | Post-starter flow | Adding a trigger/input keeps composition moving with a side inspector and `Add next node` compatible suggestions. | Planned |
| P1 | Empty canvas | Empty graph guides the user toward agent/tool/verification workflows and aligns the right rail with the current start task. | Planned |
| P1 | Harness teaching view | Default harness opens as a fitted canonical-group overview with fork/use action; raw type counts move to advanced details. | Planned |
| P1 | Naming and shape profiles | Labels and shapes communicate execution boundaries, authority, and status with text equivalents. | Planned |
| P2 | Migration compatibility | Existing stored workflows project to the new authoring taxonomy without changing canonical runtime semantics. | Planned |
| P2 | Regression harness | Static taxonomy tests and live GUI probes guard search, palette, blank run safety, harness overview, and graph activation. | Planned |

## Canonical Primitive Taxonomy

Default palette primitives:

| Primitive | Authoring meaning | Keep as separate node when |
| --- | --- | --- |
| Trigger | Starts a workflow from manual, schedule, chat, event, or webhook input. | It changes entrypoint semantics. |
| Input | Provides manual, file, media, dataset, or API payload data. | It is a durable authored source. |
| Context | Supplies repo, issue, conversation, selected run, retained state, or external context. | It changes what downstream nodes can know. |
| Agent Step | Performs model-backed reasoning over context, memory, skills, tools, and policies. | It invokes a model/agent boundary. |
| Tool Pack | Grants daemon-governed executable capabilities such as coding tools, MCP tools, browser tools, or workflow tools. | It grants tool authority or invokes tools. |
| Connector | Binds external authority, credentials, remote service context, or provider readiness. | It crosses a provider/secret/authority boundary. |
| Memory | Reads, searches, writes, injects, or governs runtime memory. | It changes memory state or explicit memory context. |
| Skills | Discovers, imports, validates, pins, selects, and injects skill context. | It changes the active skill manifest or prompt/tool context. |
| Hook | Subscribes to governed events with side-effect contracts. | The hook itself is an authored extension point. |
| Policy Gate | Blocks, routes, approves, or constrains execution. | It can pause, block, or change allowed action space. |
| Worker | Spawns, joins, resumes, cancels, or pools subagents/workers. | It creates or coordinates child execution. |
| State | Reads/writes deterministic workflow-local or runtime-projected state. | It is authored state, not merely a status row. |
| Control Flow | Branches, loops, barriers, retries, or enters subgraphs. | It changes execution topology. |
| Verification | Runs tests, assertions, doctor/readiness, diagnostics, or continuation gates. | It can pass/fail/gate continuation. |
| Recovery | Snapshots, restores, rolls back, repairs, or compacts context/workspace state. | It mutates or guards recovery state. |
| Output | Materializes a file, patch, PR draft, delivery, table, deployment, or final answer. | It creates a durable deliverable. |
| Harness / Runtime | Advanced run, task, job, checklist, package, replay, event, and projection contracts. | The user is building or debugging runtime infrastructure. |

## Node Vs Config Rule

Keep a separate node when it creates a distinct execution boundary:

- trigger or entrypoint;
- model/agent invocation;
- tool/capability grant or tool invocation;
- child worker/subagent execution;
- external connector authority or secret boundary;
- approval/review/verification gate;
- recovery mutation;
- artifact/output materialization;
- control-flow topology.

Use configuration, ports, inspector tabs, or receipts when the distinction is a
subfacet of the same boundary:

- discovery/list/fetch/status operations;
- policy fields that do not pause or block;
- runtime status rows;
- receipt/evidence/debug display;
- one operation variant of a subsystem;
- prompt injection/audit details under Skills;
- registry import/search/install/update/remove under Connector or Skills config.

## Collapse Map

| Current surface | Default primitive | Destination |
| --- | --- | --- |
| `skill_context`, `skill`, `skill_pack`, skill discovery/pinning | Skills | discovery mode, source set, selection, import/pin/trust policy, injection target, active skill-set hash, prompt audit refs |
| `hook`, `hook_policy` | Hook, or Policy Gate when blocking | hook type, side-effect contract, authority scopes, failure policy, invocation ledger |
| `model_binding`, `model_call`, `parser`, evaluator variants | Agent Step | model route, reasoning effort, structured output, parser/refinement, tool/memory/skills attachments |
| coding tool presets and tool retrieval | Tool Pack | enabled tools, dry-run/write mode, authority scopes, budget, approval, result retrieval |
| MCP server lifecycle/status/search/fetch/invoke presets | Connector plus Tool Pack | server registry/config manager, catalog search, vault refs, tool invocation config |
| subagent pool/role/spawn/join/input/result/cancel/resume | Worker | pool, role, lifecycle mode, spawn prompt, output contract, merge policy, cancellation inheritance |
| memory status/policy/search/list/remember/edit/delete | Memory | operation mode, scope, query/key, injection, retention, mutation approval |
| repository/GitHub/issue/branch/PR fragments | Context, Connector, Pull Request, Policy Gate | repo source, issue binding, branch policy, PR mode, review gate, authority scopes, artifacts |
| runtime usage/context budget/compaction policy | Policy Gate or Context Policy config | telemetry source, thresholds, warn/block/compact actions, receipts |
| runtime task/job/checklist/package/replay/projection rows | Harness / Runtime advanced | run inspector, replay state, package panel, debug palette |
| package import/export nodes | Harness / Runtime advanced or workbench action | package manifest, import review, evidence rows, locale preservation |
| rollback/restore/diagnostics repair/budget recovery | Recovery | recovery type, restore policy, repair decision, approval overrides |

## Palette Model

The node library should have three user-visible strata:

1. `Recommended`
   - canonical primitives;
   - common templates;
   - context-aware compatible-next suggestions;
   - composition helpers such as agent loop and terminal coding loop.

2. `All`
   - every default authoring primitive and curated template;
   - hidden implementation facets remain collapsed into config modes.

3. `Advanced`
   - raw runtime/protocol/debug nodes;
   - task/job/checklist/projection/package/replay internals;
   - legacy node types when useful for migration/debugging.

Required metadata on node definitions and creator presets:

- `canonicalPrimitive`;
- `paletteVisibility: "default" | "template" | "advanced" | "hidden"`;
- `collapseTarget`;
- `displayLabel`;
- `advancedLabel`;
- `description`;
- `searchAliases`;
- `configSections`;
- `runtimeMapping`;
- `shapeProfile`;
- `migrationCompatibility`.

## Search Rules

Search must reflect author intent before implementation metadata.

Ranking order:

1. exact label match;
2. canonical primitive match;
3. search alias match;
4. template/macro match;
5. description match;
6. runtime type/config/port metadata match;
7. advanced/debug matches.

Required synonym coverage:

| Query | Expected default result |
| --- | --- |
| `agent` | Agent Step, Agent loop template |
| `model` | Agent Step, model route config |
| `worker` | Worker |
| `subagent` | Worker |
| `terminal` | Terminal coding loop template, Tool Pack with coding tools |
| `coding loop` | Terminal coding loop template |
| `repo` | Context / Repository template |
| `repository` | Context / Repository template |
| `pull request` | Pull Request / Review Gate |
| `pr` | Pull Request ranked above incidental matches |
| `skills` | Skills |
| `hooks` | Hook |
| `memory` | Memory |
| `mcp` | Connector / Tool Pack |
| `policy` | Policy Gate |
| `approval` | Policy Gate / Review Gate |
| `output` | Output |

Composition helpers must be searchable. Querying `terminal` must not return zero
when the terminal coding-loop helper exists.

## UX Rules

### Empty Canvas

The empty canvas should start with a guided authoring question and a task-aligned
right rail.

Required behavior:

- right rail defaults to `Start` or `Guide`, not `Outputs`;
- starter metadata is simplified by default;
- advanced metadata appears on hover/details;
- starter options include:
  - `Agent workflow`;
  - `Tool workflow`;
  - `Verification workflow`;
  - `Start from scratch`;
- raw trigger/input cards remain available under start-from-scratch.

### Add Node Drawer

Required behavior:

- primary header button says `Add node`;
- canvas compact action says `Open palette`;
- no duplicate ambiguous `Add` names;
- drawer has `Recommended`, `All`, and `Advanced`;
- composition helpers are searchable and pinned in Recommended;
- compatible-next suggestions are visible after selecting a node;
- group labels use the canonical taxonomy, not overloaded runtime buckets.

### Node Configuration

Default node configuration should not interrupt composition.

Required behavior:

- first-run starter nodes open a side inspector by default;
- `Add next node` is a primary action;
- irrelevant config fields are hidden by selected mode;
- dense full modal remains available as `Advanced configuration`;
- compatible suggestions can be inserted without closing a blocking modal.

### Harness Teaching View

The default harness should teach the canonical topology before showing raw
runtime internals.

Required behavior:

- opens fitted to a canonical-group overview;
- shows clear `Fork editable copy` / `Use as template` action;
- defaults to collapsed groups:
  - input;
  - context;
  - skills;
  - memory;
  - tools;
  - agent step;
  - policy;
  - verification;
  - recovery;
  - output;
- read-only/block state is explained in user terms;
- raw type-count legend moves to advanced/runtime details.

### Shape Profiles

Shapes and status should communicate execution semantics, not registry clutter.

Shape profile dimensions:

- execution boundary: source, model, tool, gate, worker, state, output;
- authority boundary: read, write, approval, external connector, secret-backed;
- run state: idle, ready, blocked, warning, running, passed, failed;
- evidence posture: receipts available, replayable, fixture-backed, live-backed.

Accessibility requirements:

- accessible node names use display labels, not only runtime type ids;
- color/status badges have text equivalents;
- drawer, inspector, timeline, approvals, and run controls are keyboard
  reachable;
- icon-only buttons have clear labels and tooltips;
- localization of chrome strings must not alter runtime semantics or manifests.

## Runtime Mapping Requirements

Every default primitive must declare:

- runtime component or adapter backing;
- daemon/API route or manifest field when applicable;
- policy and authority scope fields;
- receipt/artifact/event refs emitted by activation;
- replay source for UI state;
- graph/node id mapping;
- validation/readiness checks.

React Flow may cache authoring config and projection state, but must rebuild
runtime state from canonical events, receipts, artifacts, and manifests.

## Migration Plan

Migration must be projection-first and compatibility-safe:

1. Add taxonomy metadata without changing stored graph format.
2. Preserve existing node `type` values and logic payloads.
3. Add display projection helpers:
   old type plus logic -> default primitive plus config path.
4. Add advanced inspector entries for canonical runtime ids and legacy type ids.
5. Add migration tests that load representative old workflows and verify:
   - graph opens;
   - runtime manifest is unchanged;
   - display label and palette category are updated;
   - advanced/runtime details still show raw ids.
6. Only introduce stored manifest migrations after the projection behavior is
   stable and tested.

## Implementation Sequence

### Slice 1: Run Crash Guard

Goal: restore trust in the authoring loop.

Implement:

- composer-side validation before run activation;
- fail-closed blank/invalid workflow state;
- durable blocked-run or validation evidence if an attempted run is recorded;
- guard `useChatPlaybookRuns` against missing transform callback;
- Playwright regression for blank composer `Run`.

Acceptance:

- blank workflow `Run` never navigates to a render-blocked route;
- user sees a composer-local validation/readiness message;
- run history is either unchanged or contains a durable blocked attempt;
- targeted unit and GUI tests pass.

### Slice 2: Taxonomy Metadata Contract

Goal: create an executable map before UI refactor.

Implement:

- canonical primitive enum/type;
- palette visibility metadata;
- collapse targets;
- display and advanced labels;
- search aliases;
- runtime mapping skeletons;
- static tests that every node definition and creator preset is classified.

Acceptance:

- no node/preset is unmapped;
- default vs advanced intent is explicit;
- existing runtime behavior is unchanged.

### Slice 3: Search And Palette Ranking

Goal: make common authoring words work.

Implement:

- search aliases and ranking;
- searchable composition helpers;
- query coverage for worker, terminal, agent, pull request, repo, skills,
  memory, tool, policy, approval, output;
- search tests over the node library model.

Acceptance:

- the required synonym table passes;
- `pr` no longer drowns Pull Request intent;
- `terminal` finds the terminal coding-loop helper;
- advanced/debug matches rank below default authoring primitives.

### Slice 4: Default / Advanced Palette Split

Goal: make the default drawer calm without removing runtime power.

Implement:

- drawer tabs for Recommended, All, Advanced;
- canonical group labels;
- visibility filtering;
- advanced/runtime details retained;
- recommended composition helpers.

Acceptance:

- default palette shows canonical primitives/templates;
- advanced palette exposes raw runtime/protocol/debug nodes;
- existing drag/click insertion still works;
- screenshots show less registry clutter.

### Slice 5: Collapsed Primitive Config

Goal: move subsystem facets into typed config.

Implement in this order:

1. Skills.
2. Memory.
3. Tool Pack.
4. Worker.
5. Agent Step.
6. Repository / Pull Request / Review Gate.
7. Hook / Hook Policy.

Acceptance:

- old nodes project to new primitive labels/config sections;
- new authoring primitives compile to the same runtime contracts;
- config sections expose mode/source/policy/authority fields;
- advanced details retain raw node ids and receipt refs.

### Slice 6: Post-Starter Composition Flow

Goal: keep graph building fluid after the first node.

Implement:

- side inspector default for starter nodes;
- primary `Add next node` action;
- compatible suggestions outside blocking modal;
- mode-specific config field visibility.

Acceptance:

- adding Manual Trigger does not trap the user in a dense modal;
- compatible next nodes can be inserted directly;
- advanced modal remains available.

### Slice 7: Harness Teaching View

Goal: make the default harness a teaching artifact and template source.

Implement:

- fitted canonical-group overview;
- `Fork editable copy` / `Use as template`;
- collapsed group labels;
- raw runtime type legend moved to advanced details;
- live GUI probe for opening harness and finding canonical groups.

Acceptance:

- first view communicates the canonical harness topology;
- read-only/block status has a plain-language explanation;
- advanced runtime proof remains inspectable.

### Slice 8: Migration And Regression Net

Goal: lock in the new authoring language.

Implement:

- representative old workflow fixtures;
- static taxonomy coverage tests;
- search tests;
- React Flow GUI probes;
- manifest compatibility assertions;
- replay/projection checks.

Acceptance:

- existing workflows open and run through the same runtime contracts;
- every default primitive has a regression guard;
- no React Flow shadow truth is introduced.

## Validation Plan

Static validation:

- taxonomy coverage test for every node definition and creator preset;
- collapse map projection tests;
- search ranking tests;
- manifest compatibility tests.

Runtime validation:

- invalid/blank run fail-closed test;
- default harness load/projection test;
- workflow activation manifest test for a canonical agent workflow;
- replay from runtime events/receipts into compositor state.

GUI validation:

- open Workflows from home/activity bar;
- open empty canvas and assert guided starters;
- search required synonyms;
- add Manual Trigger and insert a compatible next node;
- open advanced palette and verify raw runtime nodes still exist;
- open default harness and assert canonical group overview;
- click Run on blank graph and assert no render-blocked route.

Accessibility validation:

- keyboard navigate drawer, inspector, timeline, approvals, and run controls;
- assert accessible names for icon buttons and node cards;
- assert text equivalents for statuses and colors.

## Anti-Patterns To Avoid

- Do not create a second runtime for React Flow.
- Do not store daemon/run truth in a React Flow-only shadow store.
- Do not hide runtime contracts so deeply that protocol/debug users lose access.
- Do not collapse separate execution boundaries into one mega-node.
- Do not keep every runtime operation in the default palette.
- Do not let broad metadata search outrank user-facing primitive intent.
- Do not localize runtime semantics, ids, manifest fields, or receipt meanings.
- Do not claim completion without live GUI and runtime validation.

## Definition Of Done

This sprint is complete when:

- blank/invalid composer runs fail closed without render crashes;
- every node and creator preset maps to a canonical primitive and palette
  visibility;
- the default palette exposes canonical authoring primitives rather than raw
  runtime facets;
- advanced palette/inspectors expose all runtime contracts needed for debug and
  protocol work;
- search returns expected primitives for common authoring words;
- composition helpers are searchable;
- adding a starter node naturally offers compatible next actions;
- the default harness teaches the canonical workflow topology before exposing
  raw runtime internals;
- existing workflows remain compatible through projection/migration helpers;
- static, runtime, GUI, and accessibility validation are in place.

## Immediate Tactical Recommendation

Start with Slice 1, the blank composer `Run` crash guard.

Reason: it is the only audited issue that breaks the basic authoring loop. Once
`Run` fails closed safely, proceed to Slice 2 and make the taxonomy executable
before changing palette layout.
