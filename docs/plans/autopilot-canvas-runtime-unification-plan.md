# Autopilot Canvas Runtime Unification Plan

Last updated: 2026-03-28
Owner: Autopilot shell / Mission Control / Agent IDE / Studio follow-on
Status: post-Studio follow-on plan rebased on shipped Studio foundation

## Shipped Studio foundation

`docs/plans/autopilot-studio-artifact-real-output-convergence-plan.md` is now
the canonical Studio artifact baseline and convergence reference.

The current baseline this plan builds on is:

- `Studio` is the top-level creation surface in the shell.
- The Studio conversation lane starts fullscreen and reveals the artifact
  surface as an expandable drawer once work is materialized.
- The shared artifact host now exposes one typed step-pipeline model for every
  artifact session rather than treating verification as an isolated sidebar
  concern.
- When the active Studio artifact uses the `workspace_surface` renderer, that
  drawer now opens into the implementation surface by default rather than
  stopping at a logical placeholder shell.
- That workspace renderer surface behaves like a single primary work area:
  preview-first when ready, code/files/search/source-control/terminal as
  tabs, and an optional details rail for receipts/facts instead of a duplicated
  explorer-style control column.
- Studio is artifact-first and creates artifacts immediately for
  design/development/build-oriented prompts.
- Artifacts can resolve to document, visual, interactive single-file,
  downloadable, workspace-project, or bundle outcomes.
- Workspace-surface artifacts have kernel-owned renderer sessions, typed
  planning outputs, deterministic `vite-static-html` and `react-vite`
  scaffolding, supervised install/build/preview verification, and receipt
  capture.
- The shipped `vite-static-html` path now semantically differentiates website
  families such as agency, hospitality, sport/editorial, and product-launch
  outputs rather than routing every HTML-page request into one generic layout.
- Preview, code, files, search, source control, and plane-local terminal lenses
  are available through the embedded workspace substrate when the renderer is
  `workspace_surface`.
- The shell-global drawer remains reserved for shell-native telemetry.
- Kernel authority still governs planning, approvals, routing, and receipts.
- Verification-backed replies now outrank worker prose for Studio outcomes.
- `ioi-cli` now shares the Studio artifact contract and can inspect, validate,
  query/route, compose replies for, and materialize artifact manifests from the
  command line with either local inference fixtures or a localhost runtime path
  when routing proof is required.
- Local dev testing can now use isolated data profiles plus kernel rehydration
  of installed local engine assets so clean runs stay fast.
- `AUTOPILOT_LOCAL_GPU_DEV=1` now resolves to a shipped `ollama-openai` dev
  preset with a persistent host-side model cache, default generation +
  acceptance-model provisioning, embedding-model provisioning, and truthful
  `inference_unavailable` fail-fast behavior when the local runtime is not
  present or healthy.
- The desktop dev launcher now auto-builds and auto-starts the repo's
  `ioi-local` kernel companion for that same profile, so the one-command local
  GPU workflow boots both Studio and the kernel together instead of relying on a
  separately mounted public API.
- That same local desktop flow now waits for the local runtime health endpoint
  before Studio setup completes, which prevents first-request hangs caused by
  the shell or kernel racing a still-starting local runtime.
- The `ioi-local` companion now builds with the PoA-capable feature contract
  that matches the shipped single-node local consensus configuration.
- That same local GPU profile now skips wallet-backed connector bootstrap by
  default so canvas and Studio iteration stay centered on the local runtime
  path; set `AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP=1` when you explicitly want
  to exercise the wallet sync path.

## Purpose

This document describes the next high-level plan to tackle on top of the now
completed Studio foundation.

The shipped Studio baseline establishes:

- `Studio` as the top-level creation surface
- artifact-first creation
- typed routing between conversation, widget, visualizer, and artifact
- an artifact manifest plus renderer registry
- a workspace subsystem for preview, code, files, search, source control, and
  terminal when the active renderer is `workspace_surface`

This follow-on plan describes how the runtime canvas should evolve once that
foundation exists, so that:

- the canvas becomes the native execution-topology language for Autopilot
- interfaces/apps become first-class exposed surfaces without collapsing into
  file trees
- higher-order domain/runtime configuration stays adjacent to the graph rather
  than being forced into it
- workspace utilities remain embedded subsystems rather than taking over the
  shell

This should remain a high-level plan while the Studio foundation stays stable
and while the next canvas/runtime moves are evaluated against that shipped
baseline rather than against the older pre-Studio shell.

## Core doctrine

The post-Studio canvas direction should preserve four rules.

### 1. Keep VS Code as a subsystem

Explorer, search, source control, diffing, and text editing can use
VS Code-derived or Monaco-backed primitives.

They should remain:

- build utilities
- workspace utilities
- embedded subsystems

They should not define:

- top-level shell identity
- canvas ontology
- runtime modeling language

### 2. Make the canvas the execution language

The canvas should become the primary way to model:

- workflow topology
- worker orchestration
- approvals and policy gates
- verification and receipts
- interface ingress/egress
- service/runtime exposure

The canvas should not try to become the sole editor for every surrounding
domain concept.

### 3. Keep domain metadata out of the graph when it is not graph-native

Identity, policy roots, publication state, governance posture, settlement
details, deployment targets, and similar sovereign/domain configuration should
mostly live in:

- inspector panels
- config tabs
- domain overview pages
- manifests/spec sheets

The graph should remain operationally legible.

### 4. Keep runtime and embedded operations inside the native shell

Autopilot should not fork into a personal assistant app, a builder app, and a
robot runtime console.

It should remain one native shell with multiple first-party lenses over the
same ontology and control plane.

Initial native lenses should be:

- Personal
- Builder
- Operator
- Runtime / Fleet

A later `Embodied` lens is acceptable only when device or robotics supervision
still fits the same operator, policy, capability, inbox, and receipt model.

Extensions may later contribute domain dashboards or secondary panels, but they
should not own primary shell identity or top-level navigation while the core
ontology is still stabilizing.

## Where the current canvas stands

The current canvas foundation is already visible in the repo through the
`agent-ide` editor stack:

- the central graph editor in
  `packages/agent-ide/src/features/Editor/Canvas/Canvas.tsx`
- the overall editor shell in
  `packages/agent-ide/src/AgentEditor.tsx`
- the right-side inspector in
  `packages/agent-ide/src/features/Editor/Inspector/Inspector.tsx`

Today that stack is still fundamentally a single workflow graph editor with:

- a ReactFlow canvas
- left Explorer
- right Inspector
- bottom Console

It is a useful starting point, but it does not yet express the broader
multi-altitude runtime model discussed for Autopilot's long-term direction.

## Target end state

By the time this plan is executed, the Studio guide should already have
produced:

- artifact-first Studio creation
- artifact manifests and renderer sessions
- workspace-surface implementation lenses
- a stronger shell/workspace separation

On top of that, the desired canvas end state should look like this:

### Layer 1: Native shell

The shell continues to own:

- top-level navigation
- lens selection and project-context defaults
- project scope
- operator pane
- runs
- inbox
- capabilities
- policy
- settings
- receipts/evidence framing

### Layer 2: Execution canvas

The canvas becomes the main runtime-construction language for:

- workflows
- worker orchestration
- worker pipelines
- app/interface ingress nodes
- API/service exposure nodes
- verification checkpoints
- receipt/publication checkpoints where graph-native

### Layer 3: Interface and artifact surfaces

Interfaces and artifacts become sibling objects in the project rather than
being reduced to graph nodes alone.

That means:

- the graph can reference an `App / Interface` node
- the detailed implementation of that interface lives in Studio artifact
  surfaces, including `workspace_surface` when needed
- the runtime topology and the exposed product surface stay linked but not
  collapsed into one editor

### Layer 4: Domain and sovereign metadata

Higher-order runtime/domain configuration lives mostly outside the graph in:

- inspector panels
- top headers
- tabs such as:
  - `Graph`
  - `Interface`
  - `Policy`
  - `Publication`
  - `Receipts`
  - `Deployments`

## Object model after Studio

The cleaner ontology after Studio should be:

### Project

The scoped environment that owns:

- root/workspace
- workflows
- interfaces/apps
- artifacts
- policies
- runs
- utilities

### Objects

The things a user is actually building:

- workflow
- interface/app
- worker
- service candidate
- runtime/domain later

### Native surfaces

The shell-native surfaces through which those objects are edited or operated:

- Studio
- Workflows / Canvas
- Runs
- Inbox
- Capabilities
- Policy
- Settings

### Native project lenses

Those same shell-native surfaces should be recomposed into a small set of
first-party lenses over one ontology:

- Personal
- Builder
- Operator
- Runtime / Fleet

These lenses should change defaults, density, pinned panels, and attention
posture. They should not introduce different primary ontologies or separate
product shells.

A later `Embodied` lens can be added when device or robotics supervision still
fits the same operator, policy, capability, inbox, and receipt model.

The preferred lens should usually follow project context and may be pinned per
project or scope.

### Utilities

Supporting panes that help with implementation but are not first-class business
objects:

- Explorer
- Search
- Source Control
- Terminal
- Logs / Trace / Receipts

This keeps the graph and workspace in the right relationship:

- the graph models runtime logic
- the workspace edits concrete implementation artifacts

## Multi-altitude canvas model

The same canvas system should eventually support multiple altitudes.

### 1. Workflow view

The primary operational graph.

Shows:

- triggers
- workers
- routes
- approvals
- capabilities
- artifacts
- outputs

### 2. Worker pipeline view

A selected worker can open a pipeline-level view.

Shows:

- objective intake
- plan
- context load
- retrieval
- tool selection
- execution
- verification
- escalation
- summary / receipt emission

This prevents workers from remaining black boxes without forcing all internals
into the top-level graph.

### 3. Domain or service view

A higher-order runtime/domain lens.

Shows:

- app/interface ingress
- APIs
- operator surfaces
- policy or trust boundaries
- publication/receipt checkpoints
- worker clusters

This is where intelligent blockchain/service/runtime composition can be made
legible without flattening everything into one workflow.

## Node families

The post-Studio canvas should broaden beyond the current agent graph categories.

### Core execution nodes

- Trigger
- Worker
- Route
- Skill
- Tool
- Approval
- Policy Gate
- Verification
- Receipt Checkpoint
- Artifact Output

### Surface nodes

- App / Interface
- API Endpoint
- Install Surface
- Operator Console
- Dashboard

### Domain nodes

Use sparingly:

- Domain Boundary
- Publication Checkpoint
- Settlement Checkpoint
- Coordinator
- External Trust Anchor
- Context Store

These should be enough to express the runtime side of the system without making
the graph unreadable.

## Relationship between canvas and interfaces

This plan assumes a future where interfaces are not forced entirely into the
canvas.

The clean split is:

- canvas = runtime and orchestration structure
- interfaces surface = detailed exposure and app configuration

That means:

- a node on the graph can say “this runtime exposes an interface”
- the full implementation and configuration of that interface lives in Studio or
  a future dedicated Interfaces surface

This keeps the graph structural and the interface authoring surface practical.

## Relationship between canvas and artifacts

After the Studio guide completes, artifacts should already exist as real
implementation objects with renderer-specific delivery.

This follow-on plan should then unify them with the canvas by making the
relationship explicit:

- a workflow may reference one or more interface/app artifacts
- an interface/app artifact may link back to a workflow
- a workspace-surface artifact can be opened from the graph without turning the
  graph itself into a code editor

The important rule is:

> clicking a graph node can open an artifact, including a workspace-surface
> artifact, but the graph and the artifact remain different lenses on the same
> project object model.

## Workspace role after Studio

The workspace subsystem should remain a supporting implementation layer.

It should continue to own:

- file explorer behavior
- project search
- source control
- diffing
- text editing
- terminal and bottom-panel build tools

It should not become the organizing principle for the canvas.

In practice that means:

- the canvas can open or reveal files when needed
- workspace-surface artifacts can mount the workspace subsystem
- workflow and domain modeling should not be constrained by filesystem shape

## High-level implementation phases

This plan should be tackled only after the Studio guide is meaningfully
complete.

### Phase 1: Reframe the current canvas as workflow view

Take the current `agent-ide` graph editor and explicitly define it as the
`Workflow` altitude rather than the whole runtime language.

Outcome:

- clearer scope for the existing canvas
- easier evolution path without requiring a full rewrite first

### Phase 2: Expand the node ontology

Introduce node families for:

- interfaces
- verification/receipt checkpoints
- policy gates
- service/API exposure
- domain boundaries

Outcome:

- the graph can model more of Autopilot's runtime reality without becoming
  purely code/agent-centric

### Phase 3: Add drill-down pipeline views

Allow selected workers to open pipeline-level subviews or nested graphs.

Outcome:

- workers stop being opaque boxes
- top-level graphs remain legible

### Phase 4: Add domain/service altitude

Introduce a domain or service-level graph lens that can show:

- ingress surfaces
- trust boundaries
- publication or receipt checkpoints
- worker clusters

Outcome:

- intelligent blockchain / runtime concepts become expressible without turning
  the canvas into a giant flat workflow

### Phase 5: Bind graph nodes to real artifacts and interfaces

Connect:

- app/interface nodes
- workflow nodes
- artifacts, including workspace-surface artifacts

Outcome:

- the user can move naturally between runtime graph and implementation surface

### Phase 6: Move non-graph-native metadata into surrounding panels

Strengthen:

- right inspector
- top headers
- tabs for policy/publication/deployments/receipts

Outcome:

- the graph stays readable
- the domain becomes richer without overloading node count

### Phase 7: Consider a dedicated Interfaces surface

Only after the graph/object model is coherent, decide whether Interfaces should
graduate into its own top-level activity-bar item or remain nested under Studio.

Outcome:

- cleaner shell hierarchy
- interface authoring can mature without distorting the graph

## Acceptance criteria

This follow-on plan should only be considered complete when all of the
following are true:

- the canvas clearly supports workflow topology as its primary altitude
- worker pipeline drill-down exists or is structurally supported
- the graph can express interface/app ingress and service exposure nodes
- domain/runtime metadata is mostly expressed in surrounding panels rather than
  forced into the graph
- artifacts and graph objects can link to each other cleanly
- workspace utilities remain embedded subsystems rather than becoming the shell
  identity
- the graph language feels native to Autopilot rather than like a dressed-up
  IDE or generic node editor

## Non-goals

This plan does not aim to:

- turn the whole shell into VS Code
- make Explorer/Search/SCM top-level product objects
- force every interface into the graph editor
- force every domain concept into a node
- collapse Studio, artifacts, and Canvas into one undifferentiated surface

## Compact doctrine

Build the autonomous system in the canvas.

Implement concrete artifacts in Studio.

Keep workspace tools embedded.

Keep the shell native.
