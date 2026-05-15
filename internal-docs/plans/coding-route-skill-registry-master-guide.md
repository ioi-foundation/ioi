# Coding Route Skill Registry Master Guide

Last updated: 2026-05-10
Owner: Autopilot runtime / workflow substrate / skill registry / coding route
Status: next target end-state guide grounded in current implementation

Companion documents:

- `docs/plans/agent-runtime-harness-as-workflow-master-guide.md`
- `docs/plans/meta-harness-master-guide.md`
- `docs/specs/runtime/harness-change-workflow.md`
- `docs/specs/runtime/autopilot-chat-agent-ux.md`
- `docs/architecture/products/autopilot/local-app-workflow-canvas.md`
- `docs/architecture/products/autopilot/internal-product-spec.md`
- `examples/agent-skills-main/README.md`
- `examples/agent-skills-main/AGENTS.md`

## Executive Verdict

The build/debug/review route slice is now green. The runtime has crossed the
important threshold from "componentized harness" to "typed coding route
execution with evidence." The next target should therefore not be abstract
runtime structure or a large skill-library import. The next target is a
self-improving coding-worker substrate:

```text
route run
  -> skill selected from runtime registry
  -> model consumes skill_context through explicit graph context
  -> phase produces evidence
  -> gate/verifier/reviewer judges outcome
  -> benchmark record updates route and skill confidence
  -> skill is promoted, demoted, or marked stale
```

`examples/agent-skills-main` should still be treated as more than a pattern
library, but it should enter the system as Draft registry candidates with
provenance and phase tags. It should not be copied wholesale into runtime
prompts and it should not become a hidden controller. Skills remain bounded
guidance. Runtime routes, gates, evidence, and promotion policy remain the
authority.

The durable shape remains:

```text
intake -> classify -> resolve skills -> context -> define/spec
       -> plan -> build in slices -> verify -> review -> ship/closeout
```

The clean end state before retiring this plan is not "we have many skills." It
is:

```text
typed coding routes
  -> explicit phase topology
    -> skill_context as bounded guidance
      -> phase-aware harness components
        -> typed gates and receipts
          -> benchmark-backed skill promotion
            -> operator-visible evidence
```

The workflow canvas must remain the executable and graphical composition layer.
Routes, phase nodes, verifier/reviewer branches, and skill_context edges should
be buildable, forkable, saveable, validatable, runnable, and inspectable from
Autopilot GUI workflows.

The first product primitive is the coding route contract, not the imported
skill pack. A skill importer is necessary, but it should feed route phases
rather than become the center of the system. Route contracts define the lanes,
phase gates, and evidence surface. Skills then become selected, receipt-backed
fuel inside those lanes.

In short:

```text
coding route pipeline
  uses workflow templates and phase gates
    which use skill_context nodes
      backed by runtime skill registry entries
        imported, validated, and promoted from skill packs
```

The first implementation tranche has proved three canonical routes:

- `coding.template.build`
- `coding.template.debug`
- `coding.template.review`

The next tranche should harden those routes into a promotion loop. Only after
that loop is trustworthy should `coding.template.ship` become a target. Ship is
where release, rollback, security, and authority semantics get heavier; it
should consume a proven route/gate/promotion substrate rather than debug it.

## Current Codebase Truth

This guide assumes the current local codebase state as of 2026-05-10.

### Implemented Baseline

The current green baseline includes:

- first-class `skill_context` workflow node and runtime resolver
- `workflow.skill-context.v1` node artifact with discovery/read evidence refs
- runtime-registry-backed skill catalog access for workflow runs
- route contract types for build/debug/review
- route catalog for:
  - `coding.template.build`
  - `coding.template.debug`
  - `coding.template.review`
- deterministic classifier rules for build/debug/review
- route evidence emitted on workflow runs:
  - `coding.route.classification.v1`
  - `coding.route.phase.start.v1`
  - `coding.route.phase.complete.v1`
  - `coding.route.skill_selection.v1`
  - `coding.route.gate.v1`
- build/debug/review workflow templates with explicit
  `source -> skill_context -> model(context) -> output` graph wiring
- route evidence displayed in workflow run details
- harness tools for route catalog access and thin Draft skill-pack import
- GUI harness proof for route create, save, validate, run, and inspect

Latest green evidence:

- `docs/evidence/autopilot-gui-harness-validation/2026-05-10T18-50-49-294Z/result.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-10T18-50-49-294Z/workflow-coding-route-proof.json`
- `docs/evidence/autopilot-gui-harness-validation/2026-05-10T18-50-49-294Z/workflow-skill-context-proof.json`

The literal Cargo command with two test-name filters is not valid Cargo syntax:

```text
cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml coding_route workflow_skill_context -- --nocapture
```

Use the equivalent split commands:

```text
cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml coding_route -- --nocapture
cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_skill_context -- --nocapture
```

### Runtime Skill Registry

The runtime already has a canonical skill catalog shape in
`apps/autopilot/src-tauri/src/models/knowledge.rs`.

`SkillCatalogEntry` includes:

- `skill_hash`
- `name`
- `description`
- `lifecycle_state`
- `source_type`
- `success_rate_bps`
- `sample_size`
- `archival_record_id`
- `source_session_id`
- `source_evidence_hash`
- `relative_path`
- `stale`
- `definition`

The registry is exposed through Tauri commands:

- `get_skill_catalog`
- `get_skill_detail`

Those commands are wired in `apps/autopilot/src-tauri/src/lib.rs` and loaded
from `apps/autopilot/src-tauri/src/kernel/data/commands/skill_context.rs`.

The TypeScript runtime adapter in `apps/autopilot/src/services/TauriRuntime.ts`
already exposes:

- `getSkillCatalog()`
- `getSkillDetail(skillHash)`
- `listWorkflowSkillCatalog(projectRoot)`

`listWorkflowSkillCatalog` intentionally adapts registry entries into the
workflow-facing shape by calling `getSkillCatalog()` and then
`getSkillDetail(skill.skill_hash)` for markdown.

### Workflow Skill Context Node

The workflow node registry already includes `skill_context` in
`packages/agent-ide/src/runtime/workflow-node-registry.ts`.

Current node contract:

- type: `skill_context`
- label: `Skill Context`
- group: `AI`
- family: `context`
- token: `SK`
- input: payload
- output: payload
- outputs: `output`, `error`
- executor: `workflow.skill_context`
- no side effects
- required evidence: `execution`, `schema_validation`
- completion requirements: `execution`, `verification`

The default logic is:

```json
{
  "skillContext": {
    "mode": "discover",
    "goalSource": "node_input",
    "goal": "",
    "minScoreBps": 6500,
    "maxSkills": 3,
    "onNoMatch": "warn",
    "pinnedSkills": [],
    "onMissingPinned": "block",
    "includeMarkdown": true,
    "guidanceMaxChars": 1800
  }
}
```

The output schema is `workflow.skill-context.v1` and contains:

- `status`
- `mode`
- `goal`
- `selectedSkills`
- `promptContext`
- `evidenceRefs`

### Runtime Resolver

`apps/autopilot/src-tauri/src/project/runtime.rs` defines
`WorkflowSkillResolver`.

Current resolver behavior:

- Receives a skill catalog snapshot from workflow run options.
- Supports `skillCatalog` and `workflowSkillCatalog`.
- Resolves pinned mode by `skillHash` first.
- Resolves name-only pins only when exactly one matching skill exists.
- Blocks missing pinned skills by default.
- Discovers skills by deterministic scoring against goal text.
- Excludes stale skills and only discovers lifecycle states containing
  `validated` or `promoted`.
- Emits `workflow.skill-context.v1`.
- Emits evidence refs such as:
  - `workflow.skill_context.discovery.v1:<node-id>`
  - `workflow.skill_context.pinned.v1:<node-id>`
  - `workflow.skill_context.read.v1:<skill-hash>`

Model nodes already receive skill context explicitly through their existing
input graph path. The runtime attaches the selected context under model
attachments as `skillContext`.

### Workflow Commands

`apps/autopilot/src-tauri/src/project/commands.rs` now constructs a
`WorkflowSkillResolver` for:

- `run_workflow_project`
- `run_workflow_node`
- `dry_run_workflow_node`

The important architecture point is that app state and registry snapshots are
resolved before execution. The workflow engine receives a resolver. It does not
scan user skill directories at execution time.

### Harness Tools

`packages/agent-ide/src/runtime/workflow-harness-tools.ts` now exposes:

- `workflow.catalog.skills`
- `workflow.catalog.coding_routes`
- `workflow.skills.import_pack`

The skill catalog tool calls runtime API `listWorkflowSkillCatalog` and returns
receipt evidence that catalog access came through the runtime registry API. The
route catalog tool calls `listWorkflowCodingRoutes`. The import tool calls
`importWorkflowSkillPack`, which uses the existing skill source machinery to
import a source as Draft rather than scanning files during workflow execution.

This is the right primitive for scripted harness flows that need to prove skill
catalog access before running or validating skill-context workflows.

### Coding Route Runtime

`packages/agent-ide/src/runtime/workflow-coding-routes.ts` defines the current
route catalog for build/debug/review.

`apps/autopilot/src-tauri/src/project/templates.rs` defines runtime workflow
templates for the same three routes. Each template uses a `skill_context` node
and an explicit context edge into the model node.

`apps/autopilot/src-tauri/src/project/runtime.rs` classifies routes, emits route
evidence, includes selected skill hashes in route evidence, and mirrors route
evidence into verification evidence for run inspection.

`packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx` exposes the
run's route id, phase, selected skill count, gate status, and evidence refs.

### GUI Harness Proof

`scripts/lib/autopilot-gui-harness-contract.mjs` includes the required
artifacts:

- `workflow_skill_context_create_run`
- `workflow_coding_route_create_run`

It also includes runtime consistency:

- `workflow_skill_context_create_run_proof_present`
- `workflow_coding_route_create_run_proof_present`

`scripts/lib/autopilot-gui-harness-validation/core.mjs` statically verifies the
skill-context and coding-route implementations. It writes both workflow
skill-context and workflow coding-route proof artifacts.

The latest live GUI validation evidence from the route implementation pass is
under:

- `docs/evidence/autopilot-gui-harness-validation/2026-05-10T18-50-49-294Z/`

### Example Skill Pack Shape

`examples/agent-skills-main` contains:

- `skills/*/SKILL.md` lifecycle skills
- `.claude/commands/*.md` slash command wrappers
- `agents/*.md` specialist personas
- `hooks/*.sh` and hook docs
- `references/*.md` checklists and orchestration patterns
- `.claude-plugin/plugin.json`
- MIT license

Its useful structure is:

```text
skills   = how to perform a phase
commands = when to run phase workflows
agents   = who reviews or reasons from a perspective
hooks    = runtime or harness policy ideas
refs     = optional phase checklists and support material
```

That maps cleanly to our runtime if we preserve the distinction.

## North Star

The target system is an adaptive coding route that can:

1. Classify the task.
2. Choose a route preset.
3. Resolve skills from the runtime registry through `skill_context`.
4. Execute or guide workflow phases.
5. Collect receipts and evidence.
6. Decide whether the work may advance to the next phase.
7. Promote successful skill and route behavior back into registry benchmarks.

The user should be able to run this casually in chat, deterministically in a
workflow, or repeatedly through a GUI harness. The same primitive should serve
all three contexts:

- chat/autopilot: discover skills when the goal is open-ended
- deterministic harness: pin skills by hash
- authoring GUI: allow name lookup and configuration, then resolve to hashes
  before production use

The product breakthrough is that the operator should eventually see route state
as an explicit object, for example:

```text
Route: normal multi-file build
Phase: verify
Skills: test-driven-development, incremental-implementation
Gate: failed because GUI harness proof is missing
Evidence: test output, selected skill hashes, model context, run receipt
```

That is the bar. The system should not merely report "I tested it." It should
show why a route advanced, paused, blocked, or regressed.

## Plan Retirement Target

This plan should be considered complete enough to retire only when the current
green build/debug/review route substrate has become a promotion-capable,
operator-visible coding-worker loop.

The completion target is:

```text
build/debug/review route run
  -> selects Draft or Promoted skills from registry
  -> records route, phase, skill, model-context, and gate evidence
  -> runs a benchmark or retained verification task
  -> updates skill/route confidence metadata
  -> promotes, demotes, or marks stale based on evidence
  -> remains graphically buildable, forkable, and runnable in Autopilot workflows
```

Before this guide is removed or archived, the system should satisfy these
specific conditions:

1. Route contracts and gates are non-prose typed objects.
2. `examples/agent-skills-main` can be imported as Draft with provenance.
3. Imported skills can be phase-tagged and route-tagged without promotion.
4. A tiny first skill set can be benchmarked:
   - `incremental-implementation`
   - `test-driven-development`
   - `debugging-and-error-recovery`
   - `code-review-and-quality`
   - `source-driven-development`
5. Promotion and demotion decisions are backed by retained evidence refs.
6. Phase-aware harness components map to route phases.
7. Build/debug/review routes remain editable as workflow graphs in the GUI.
8. Forked route workflows preserve route contracts, skill pins, gates, and
   evidence expectations.
9. Run details and evidence surfaces show route, phase, selected skills,
   skill lifecycle state, gate result, blocker reason, and evidence refs.
10. GUI harness proves the entire loop end to end.

Only after those conditions are green should attention shift away from this
guide to broader agent harness opportunities such as richer swarm dispatch,
new agent profiles, package promotion UX, or deeper rollback policy.

## Design Doctrine

### 1. Route Before Prompt

The coding pipeline should be a typed route, not a giant hidden prompt.

Good:

```text
source -> skill_context -> model_call(context) -> verifier -> output
```

Bad:

```text
chat wrapper silently mutates the model system prompt with whichever skill text
the model thought it wanted
```

Prompt text is still useful, but it should be emitted by nodes and attached
through explicit graph edges.

### 2. Registry Before Filesystem

`skill_context` must continue to resolve skills from the runtime registry, not
from `.cursor/skills`, Codex skill folders, or arbitrary repository scanning.

Filesystem importers may feed the registry. Runtime execution should consume the
registry.

### 3. Pinned For Production, Discover For Authoring

Discovery is good for interactive authoring, chat, exploration, and route
suggestions.

Pinned hashes are the production contract for repeatable harnesses and promoted
workflow templates.

Name-only pins are authoring convenience. They must resolve deterministically
before a workflow is treated as production-ready.

### 4. Skills Are Guidance, Not Authority

Skills do not grant tool rights. They do not execute scripts by themselves.
They are context and process guidance.

If a skill references a script, execution must still happen through normal
tool/function/workflow nodes with their own authority and evidence.

### 5. Pipeline Gates Belong To Runtime

The runtime decides:

- whether a spec is required
- whether a plan is required
- which verification commands or harnesses are enough
- whether review/security/performance gates are mandatory
- whether a change may close or ship

Skills explain how to perform a phase. They should not be the sole enforcement
mechanism for phase advancement.

### 6. Personas Are Roles, Not Routers

The example repo's `code-reviewer`, `security-auditor`, and `test-engineer`
should map to agent profiles, reviewer nodes, or fan-out workflow branches.
They should not become meta-router skills.

Avoid a generic persona whose job is "decide which persona to call." Route
selection belongs to workflow/runtime logic.

### 7. Evidence Is The Product Surface

Every meaningful phase should leave an inspectable trail:

- selected skill hashes
- skill discovery or read refs
- route classification
- phase decision
- model context attachment
- test/build/harness output
- review findings
- final closeout or ship decision

This aligns with Autopilot's broader product direction: workflows become
inspectable workers and outcomes remain replayable.

Route evidence is not bookkeeping. It is the primary product surface that lets
operators trust, debug, and improve autonomous coding work.

### 8. Componentized Harness Becomes Dispatch Topology

The componentized harness should evolve into the execution topology for coding
routes. A phase can be a local step at first, then become a dispatch surface as
the runtime matures:

- context agent
- planner agent
- builder agent
- verifier agent
- reviewer, security, and test fan-out
- merge or verdict node

This keeps the workflow canvas aligned with the actual topology of agentic
work instead of being a decorative view over hidden execution.

## Desired Object Model

### Skill Pack

A skill pack is an imported source bundle, such as `agent-skills-main`.

Fields:

- pack id
- name
- source uri
- source type
- license
- version or commit
- imported at
- importer version
- discovered skills
- discovered personas
- discovered commands
- discovered references
- source evidence hash

Skill packs are not directly executed. They provide candidates for the registry
and workflow templates.

### Skill Registry Entry

The existing `SkillCatalogEntry` is the right foundation. The target state
should retain its current fields and add or derive the following where needed:

- source pack id
- phase tags
- route tags
- trigger examples
- license attribution
- benchmark suite id
- promotion evidence refs
- conflict group
- supersedes/superseded-by links

These can be added incrementally. The current critical invariant is that
`skill_hash` remains the stable pinning key.

### Coding Route

A coding route is a typed preset that maps task conditions to phase topology.

Fields:

- route id
- label
- task class
- risk level
- default phase sequence
- required skill selectors
- optional skill selectors
- evidence requirements
- allowed skip conditions
- verifier profile
- closeout template

Routes should be inspectable and eventually editable as workflows.

### Phase

A phase is a bounded step in the coding route.

Core phases:

- `coding.intake`
- `coding.context`
- `coding.define`
- `coding.plan`
- `coding.build`
- `coding.verify`
- `coding.review`
- `coding.ship`
- `coding.closeout`

Each phase can be backed by one or more workflow nodes. A phase can pin one or
more skills, discover supporting skills, or run without skills.

### Persona / Agent Profile

A persona is a role with a perspective and output format.

Candidate profiles from `agent-skills-main`:

- `code-reviewer`
- `security-auditor`
- `test-engineer`

Target runtime placement:

- agent profile registry
- model profile node
- reviewer workflow branch
- fan-out phase template

Do not store personas as ordinary skill guidance unless the runtime lacks an
agent profile substrate. Even then, mark them clearly as role prompts.

### Workflow Template

Slash commands from `agent-skills-main` map best to workflow templates:

- `/spec` -> spec route template
- `/plan` -> planning route template
- `/build` -> build route template
- `/test` -> test route template
- `/review` -> review route template
- `/ship` -> ship route template
- `/code-simplify` -> simplification route template

Templates should use pinned skill hashes once imported and validated.

## Coding Route Pipeline

### Phase 0: Intake

Purpose:

- Understand user goal.
- Determine task class and risk.
- Decide if this is code, review, research, UI, debugging, shipping, or mixed.

Inputs:

- user request
- current repository state
- active workflow/session metadata
- prior run or issue context

Outputs:

- task class
- route candidate
- risk flags
- missing information
- initial evidence record

Route decision examples:

| Request | Route |
| --- | --- |
| "Fix this failing test" | debugging route |
| "Add a new workflow node" | normal multi-file build route |
| "Review this diff" | review route |
| "Prepare this for release" | ship route |
| "Explore this idea" | define route |

### Phase 1: Skill Resolution

Purpose:

- Attach the right phase guidance.
- Make selected skill hashes visible.
- Keep prompt assembly explicit.

Implementation:

```text
source/input -> skill_context -> model/context consumer
```

Discovery mode:

- authoring flows
- chat/autopilot flows
- exploratory route suggestions

Pinned mode:

- production harness flows
- promoted route templates
- deterministic GUI proof scenarios

Evidence:

- `workflow.skill_context.discovery.v1`
- `workflow.skill_context.pinned.v1`
- `workflow.skill_context.read.v1`
- selected skill hashes in node output and run details

### Phase 2: Context

Purpose:

- Gather only the source files, tests, specs, logs, and docs relevant to the
  route.
- Avoid flooding model context.

Candidate skills:

- `context-engineering`
- `source-driven-development`

Runtime responsibilities:

- file search and read boundaries
- source attribution
- external documentation policy
- cache and freshness controls

### Phase 3: Define

Purpose:

- Clarify fuzzy work before implementation.
- Produce a spec only when the task warrants it.

Candidate skills:

- `idea-refine`
- `spec-driven-development`

Skip conditions:

- user gave exact implementation instructions
- tiny single-file change
- pure mechanical fix

Evidence:

- assumptions or clarifying questions
- spec artifact when required
- accepted scope

### Phase 4: Plan

Purpose:

- Turn clear requirements into ordered work.
- Identify dependencies and parallelism.

Candidate skill:

- `planning-and-task-breakdown`

Required for:

- multi-file changes
- uncertain architecture
- multiple agents/workers
- public API or migration work

Evidence:

- task list
- acceptance criteria
- verification plan
- dependency graph if applicable

### Phase 5: Build

Purpose:

- Implement in small slices.
- Keep the repository in a working state.

Candidate skills:

- `incremental-implementation`
- `test-driven-development`
- `api-and-interface-design`
- `frontend-ui-engineering`
- `deprecation-and-migration`

Runtime expectations:

- edits are scoped to route task
- tools remain authority-gated
- each slice has verification
- model context includes relevant skill receipts

### Phase 6: Verify

Purpose:

- Prove behavior with tests, builds, harnesses, runtime checks, or manual GUI
  proof depending on route.

Candidate skills:

- `test-driven-development`
- `browser-testing-with-devtools`
- `debugging-and-error-recovery`

Evidence:

- command output
- failing-to-passing proof for bug fixes
- GUI harness run when UI/runtime route requires it
- node output schema validation

### Phase 7: Review

Purpose:

- Catch quality, correctness, security, performance, and maintainability issues
  before closeout.

Candidate skills:

- `code-review-and-quality`
- `security-and-hardening`
- `performance-optimization`
- `code-simplification`
- `doubt-driven-development`

Persona candidates:

- `code-reviewer`
- `security-auditor`
- `test-engineer`

Runtime shape:

```text
review input
  -> fan-out reviewer branches when independent
  -> merge findings
  -> produce blocker/non-blocker decision
```

Use fan-out only when branches are independent and each reviewer has a distinct
perspective.

### Phase 8: Ship / Closeout

Purpose:

- Decide whether work is complete.
- Preserve what changed, what was verified, and what remains.

Candidate skills:

- `shipping-and-launch`
- `git-workflow-and-versioning`
- `documentation-and-adrs`
- `ci-cd-and-automation`

For normal coding tasks, closeout can be lightweight:

- changed files
- tests run
- known gaps
- suggested next step

For production-bound work, ship should include:

- go/no-go decision
- blockers
- rollback plan
- monitoring or harness evidence
- accepted risks

## Adaptive Route Presets

### Tiny Route

Use for:

- typo fix
- one-function cleanup
- small test update

Shape:

```text
intake -> context -> build -> targeted verify -> closeout
```

Skill behavior:

- optional discovery
- no mandatory spec or plan

Gate:

- targeted verification must match changed surface

### Normal Multi-File Route

Use for:

- feature touching more than one file
- workflow node addition
- runtime contract change

Shape:

```text
intake -> skill_context(discover or pinned)
       -> context -> plan -> build slices -> verify -> review -> closeout
```

Likely skills:

- `planning-and-task-breakdown`
- `incremental-implementation`
- `test-driven-development`
- domain-specific supporting skill

Gate:

- tests/build/harness relevant to changed surface

### Debugging Route

Use for:

- failing test
- broken build
- runtime error
- unexpected behavior

Shape:

```text
intake -> context -> reproduce -> localize -> fix -> guard -> verify
```

Likely skills:

- `debugging-and-error-recovery`
- `test-driven-development`

Gate:

- failure reproduced or explicitly explained as unreproducible
- regression guard added when feasible

### High-Stakes Route

Use for:

- auth
- payment
- data migration
- production deploy
- public API
- irreversible operation
- unfamiliar code with high blast radius

Shape:

```text
intake -> context -> define -> plan -> build slices
       -> verify -> doubt/review/security -> ship gate
```

Likely skills:

- `spec-driven-development`
- `planning-and-task-breakdown`
- `source-driven-development`
- `doubt-driven-development`
- `security-and-hardening`
- `shipping-and-launch`

Gate:

- review and security findings classified
- rollback or mitigation documented
- user approval when authority or irreversible risk changes

### UI Runtime Route

Use for:

- Autopilot GUI
- workflow composer
- desktop shell
- canvas
- browser-visible behavior

Shape:

```text
intake -> context -> plan -> build -> browser/gui verify -> review -> closeout
```

Likely skills:

- `frontend-ui-engineering`
- `browser-testing-with-devtools`
- `test-driven-development`

Gate:

- relevant GUI harness or screenshot proof when user-visible behavior changes

### Review Route

Use for:

- "review this"
- pre-merge quality gate
- ship readiness

Shape:

```text
intake -> collect diff/context -> skill_context(pinned review)
       -> reviewer branches -> merge -> verdict
```

Likely skills:

- `code-review-and-quality`
- `security-and-hardening`
- `performance-optimization`

Gate:

- findings first
- severity labels
- file/line references
- no implementation unless explicitly requested after review

## Mapping `agent-skills-main` Into Our Runtime

### Import As Skill Candidates

The `skills/*/SKILL.md` files should be imported into the runtime registry as
candidate skills, not directly loaded by `skill_context`.

Initial lifecycle:

- external import: `Draft`
- after shape validation: `Validated`
- after benchmark and harness success: `Promoted`

Required import metadata:

- source repo/path
- license
- source pack id
- relative path
- content hash
- imported timestamp
- source evidence hash

### Classify Skills By Phase

Suggested mapping:

| Phase | Skills |
| --- | --- |
| Meta | `using-agent-skills` |
| Define | `idea-refine`, `spec-driven-development` |
| Plan | `planning-and-task-breakdown` |
| Context | `context-engineering`, `source-driven-development` |
| Build | `incremental-implementation`, `test-driven-development`, `api-and-interface-design`, `frontend-ui-engineering` |
| Verify | `debugging-and-error-recovery`, `browser-testing-with-devtools`, `test-driven-development` |
| Review | `code-review-and-quality`, `security-and-hardening`, `performance-optimization`, `code-simplification`, `doubt-driven-development` |
| Ship | `git-workflow-and-versioning`, `ci-cd-and-automation`, `deprecation-and-migration`, `documentation-and-adrs`, `shipping-and-launch` |

`using-agent-skills` should mostly become route selection and skill-selection
policy. It can remain in the registry as a meta skill for authoring, but it
should not be the hidden runtime controller.

### Convert Commands To Workflow Templates

Map example slash commands to our workflow templates:

| Example command | Runtime template |
| --- | --- |
| `.claude/commands/spec.md` | `coding.template.spec` |
| `.claude/commands/plan.md` | `coding.template.plan` |
| `.claude/commands/build.md` | `coding.template.build` |
| `.claude/commands/test.md` | `coding.template.test` |
| `.claude/commands/review.md` | `coding.template.review` |
| `.claude/commands/ship.md` | `coding.template.ship` |
| `.claude/commands/code-simplify.md` | `coding.template.simplify` |

Each template should use `skill_context` nodes. Promoted templates should pin
skill hashes.

### Convert Personas To Agent Profiles

Map example personas:

| Example persona | Runtime concept |
| --- | --- |
| `code-reviewer` | review agent profile or review node role |
| `security-auditor` | security review profile or branch |
| `test-engineer` | test coverage profile or branch |

These profiles should be callable by review and ship templates. They should not
own route selection.

### Convert Hooks To Runtime Policy Ideas

The example repo's hooks are useful, but they are not direct skills.

Potential target concepts:

- freshness-aware source documentation cache
- simplification ignore annotations
- pre-tool and post-tool receipt transformers
- verifier policy hooks

Hook behavior should be represented as typed runtime policies or harness tools,
not hidden shell scripts attached to a skill.

## Skill Registry Improvement Plan

This plan is important, but it should not outrank route contracts. The
registry work should proceed in a thin, route-serving slice first: enough
registry fixture/import capability to let route presets use real skill hashes
and `skill_context` receipts. Broad skill pack import and promotion comes after
the route substrate exists.

### Phase A: Skill Pack Importer

Build an importer that reads a local skill pack and writes registry candidate
records through existing runtime skill source machinery.

Importer responsibilities:

- locate `SKILL.md` files
- parse frontmatter
- extract name and description
- keep markdown body
- hash normalized content
- preserve relative path
- preserve license and source uri
- generate source evidence
- mark imported entries `Draft`

Non-responsibilities:

- no runtime prompt mutation
- no direct execution of skill scripts
- no automatic promotion

### Phase B: Shape Validation

Validate each imported skill:

- has name
- has description
- has clear trigger language
- markdown fits guidance clipping budgets or has references
- does not claim authority it does not have
- does not require hidden tools
- distinguishes guidance from execution
- has suitable phase tags

Output:

- validation report
- stale or rejected entries
- candidate lifecycle update

### Phase C: Benchmarking

Create benchmark tasks for each skill family.

Examples:

- TDD skill: bug fix must add failing test first
- debugging skill: agent must reproduce/localize before fix
- review skill: findings must be severity-ranked with file refs
- source-driven skill: framework-specific answer must cite official docs
- security skill: must flag obvious injection/auth issues
- shipping skill: must produce rollback plan for production-bound change

Promotion requires retained evidence, not taste.

### Phase D: Promotion

Promote a skill only when:

- shape validation passes
- benchmark success crosses threshold
- no stale source flag
- license/provenance is present
- guidance is clipped safely
- generated prompt context is useful in real workflow runs

Promoted skills become eligible for default discovery. Draft skills can still be
manually pinned in authoring contexts if the user accepts the risk.

## Next Implementation Leg

The route contract, classifier, template, and GUI proof slice is already green.
The next leg should turn that substrate into a promotion-capable coding-worker
loop.

### Step 1: Harden Route Objects

Make route contracts and phase gates stricter typed objects rather than mostly
descriptive structures.

Target schemas:

- `RouteContract`
- `RoutePhase`
- `RouteGateResult`
- `RouteSkillSelection`
- `RouteRunSummary`

Gate results should use a fixed status vocabulary:

```text
pass | warn | block | skipped
```

Required gate fields:

- `reason`
- `evidenceRefs`
- `blockingRequirements`
- `operatorOverrideAllowed`
- `overrideEvidenceRefs`
- `phaseId`
- `gateId`

The important outcome is that route state is auditable without trusting model
narrative.

### Step 2: Import And Tag Draft Skills

Import `examples/agent-skills-main` as Draft through runtime registry import
machinery.

Do not promote broadly. First preserve:

- source uri
- source type
- license
- relative path
- content hash
- source evidence hash
- imported timestamp
- lifecycle state
- markdown detail

Then add phase and route tags for a small first set:

- `incremental-implementation`
- `test-driven-development`
- `debugging-and-error-recovery`
- `code-review-and-quality`
- `source-driven-development`

Those five map cleanly to build/debug/review and are enough to prove the
system.

### Step 3: Add Benchmark-Backed Promotion

Create tiny deterministic benchmark tasks for the first five skills. Promotion
should require retained evidence, not taste.

Example benchmark expectations:

- `incremental-implementation`: narrow slices, scoped edits, verification per
  slice.
- `test-driven-development`: regression or behavior proof tied to the changed
  surface.
- `debugging-and-error-recovery`: reproduce or explain unreproducibility,
  localize cause, verify fix.
- `code-review-and-quality`: findings first, severity, file/line refs,
  residual test gaps.
- `source-driven-development`: source-grounded reasoning and freshness policy.

Promotion outputs:

- benchmark run id
- route id
- phase id
- selected skill hash
- before/after confidence
- evidence refs
- lifecycle transition
- stale/demotion reason when applicable

### Step 4: Map Harness Components To Route Phases

The componentized harness should become the route execution topology.

Initial mapping:

| Route phase | Harness component |
| --- | --- |
| `coding.intake` | context/intake component |
| `coding.context` | context agent or source selector |
| `coding.plan` | planner component |
| `coding.build` | builder component |
| `coding.verify` | verifier and completion gate |
| `coding.review` | reviewer/security/test fan-out |
| `coding.closeout` | merge/verdict/output writer |

The workflow canvas should remain the build surface for this topology. A route
workflow should be graphically editable, forkable, runnable, and inspectable in
Autopilot.

### Step 5: Improve Operator Evidence UI

Before expanding route breadth, make route evidence legible.

The operator should see:

```text
Route: debug
Phase: verify
Selected skills:
- debugging-and-error-recovery - Draft
- test-driven-development - Promoted

Gate: blocked
Reason: no failing-to-passing evidence found
Evidence:
- coding.route.classification.v1
- workflow.skill_context.discovery.v1
- workflow.skill_context.read.v1:<skill-hash>
- coding.route.gate.v1
```

This UI should appear in run details and eventually Evidence Atlas.

### Step 6: Add Ship Only After Promotion Loop

`coding.template.ship` should remain deferred until build/debug/review can run
the loop above. Ship should include reviewer fan-out, security/release gates,
rollback plan, authority checks, operator approval, and go/no-go evidence.

## Harness Validation Requirements

### Registry Import Proof

The harness should prove:

- skill pack found
- skills parsed
- license/provenance captured
- entries inserted into registry as `Draft`
- catalog command returns imported skills
- detail command returns markdown
- no direct filesystem scan occurs during `skill_context` execution

### Skill Context Proof

Already present baseline should continue:

- node visible in composer
- discover mode configurable
- pinned mode configurable
- workflow save works
- workflow validation works
- workflow run completes
- node output includes `workflow.skill-context.v1`
- evidence contains discovery/read refs
- model node attachment includes selected skill context

### Coding Route Proof

The current baseline already proves build/debug/review create, save, validate,
run, and inspect. Keep that proof green.

Baseline proof checks:

1. Launch Workflows view.
2. Create a coding route workflow from template.
3. Configure route as build, debug, or review.
4. Resolve skills from registry.
5. Save workflow.
6. Validate workflow.
7. Run workflow.
8. Confirm phase outputs and route evidence.
9. Confirm selected skill hashes are in run details.
10. Confirm final output cites verification evidence.

### Promotion Loop Proof

Add GUI harness scenarios for the next target:

1. Import `examples/agent-skills-main` as Draft.
2. Phase-tag and route-tag the first five skills.
3. Create or load a build/debug/review route workflow.
4. Select Draft and Promoted skill candidates through runtime registry APIs.
5. Run a benchmark or retained verification task.
6. Emit route, skill, model-context, benchmark, and gate evidence.
7. Update skill lifecycle/confidence/stale metadata from the evidence.
8. Fork the route workflow.
9. Confirm the fork preserves route contract, skill pins, gates, and evidence
   expectations.
10. Confirm run details and evidence surfaces show the promotion decision.

### Ship Route Proof

Add this after the promotion loop proof is green.

1. Create or load ship template.
2. Pin `shipping-and-launch`, `code-review-and-quality`,
   `security-and-hardening`, and `test-driven-development`.
3. Run reviewer branches.
4. Merge findings.
5. Produce go/no-go with rollback plan.
6. Confirm critical findings block by default.

## Acceptance Criteria For Retiring This Plan

This guide can be retired when:

1. `agent-skills-main` or an equivalent skill pack can be imported into the
   runtime registry as Draft without hand-copying skill text.
2. Imported skills preserve source path, license, content hash, lifecycle state,
   stale flag, benchmark metrics, and detail markdown.
3. Imported skills can be phase-tagged and route-tagged.
4. `workflow.catalog.skills` and `workflow.catalog.coding_routes` prove catalog
   access through runtime APIs.
5. `skill_context` can discover eligible promoted non-stale skills for chat and
   authoring routes.
6. Draft skills can be explicitly selected for benchmark runs without becoming
   default discovery candidates.
7. Promoted workflow templates pin skills by hash.
8. Build/debug/review routes emit typed route, phase, skill selection, and gate
   evidence independent of model prose.
9. Model nodes consume skill guidance only through explicit graph context.
10. Phase-aware harness components are mapped to build/debug/review route
    phases.
11. Benchmark runs can promote, demote, or stale-mark the first five skills with
    retained evidence refs.
12. GUI harness proves create, configure, save, validate, run, inspect, fork,
    and evidence-review flows.
13. Final run details show route, phase, selected skills, skill lifecycle state,
    gate status, blocker reason, and verification evidence in one inspectable
    bundle.

## Non-Goals

Do not make these moves:

- Do not turn `using-agent-skills` into a hidden universal controller prompt.
- Do not let `skill_context` scan arbitrary skill folders at runtime.
- Do not promote imported skills without benchmark evidence.
- Do not treat skill scripts as executable authority.
- Do not merge personas, skills, and route templates into one object type.
- Do not make every tiny coding task run the full define-plan-build-ship
  lifecycle.
- Do not let route discovery silently override an explicitly pinned harness.

## Open Design Questions

1. Should route templates be stored as workflow project scaffolds, runtime
   action presets, or both?
2. Should phase tags live directly on `SkillCatalogEntry`, in a sidecar index,
   or in benchmark/promotion metadata?
3. Should agent profiles have their own registry parallel to skill registry?
4. Should route classification be a workflow node, a chat runtime pre-step, or a
   shared service used by both?
5. Should imported skill markdown be normalized before hashing, or should the
   hash preserve exact upstream bytes?
6. What promotion threshold should distinguish `Validated` from `Promoted`?
7. How should stale upstream skills degrade pinned workflows: warn, block, or
   require explicit operator acceptance?

## Recommended Implementation Sequence

Completed baseline:

- Keep the existing `skill_context` primitive green.
- Define route contract schema for build, debug, and review.
- Define route evidence artifact shapes and refs.
- Implement deterministic route classifier rules for build, debug, and review.
- Implement `coding.template.build`, `coding.template.debug`, and
  `coding.template.review` using existing `skill_context`.
- Add route evidence into run details and the GUI evidence surface.
- Add GUI harness proof for create, save, validate, run, and inspect of the
  three canonical routes.
- Add a thin Draft skill-pack import path.

Next sequence:

1. Harden route contract, route phase, route gate, route skill selection, and
   route run summary schemas.
2. Import `examples/agent-skills-main` as Draft with source, license, relative
   path, content hash, detail markdown, and provenance.
3. Add phase tags and route tags for imported skills.
4. Build benchmark tasks for the first five coding skills:
   - `incremental-implementation`
   - `test-driven-development`
   - `debugging-and-error-recovery`
   - `code-review-and-quality`
   - `source-driven-development`
5. Record route + skill + gate evidence for each benchmark run.
6. Update skill confidence, lifecycle, stale flags, and route/phase confidence
   from retained benchmark evidence.
7. Map phase-aware harness components to build/debug/review routes.
8. Improve run details and evidence UI for route, phase, selected skills,
   lifecycle state, gate blockers, and promotion evidence.
9. Prove route workflow forkability: forked workflows preserve route contracts,
   skill pins, gates, and evidence expectations.
10. Add GUI harness proof for the promotion loop.
11. Add `coding.template.ship` only after the promotion loop is green.
12. Add ship route GUI proof.

## Autonomous Implementation Prompt

Use this prompt to drive the next implementation leg. It is intentionally
strict about not stopping at analysis or partial scaffolding.

```text
You are Codex working in /home/heathledger/Documents/ioi/repos/ioi.

Implement the next target end state in docs/plans/coding-route-skill-registry-master-guide.md.

Goal:
The build/debug/review route substrate is already green. Turn it into a
promotion-capable coding-worker loop. Keep skill_context and the runtime skill
registry as the only skill source during execution. Keep workflows as the
explicit graph composition layer. Implement slice by slice, validate each slice,
and continue until build/debug/review routes can select Draft or Promoted
skills, run benchmark/verification tasks, emit route + skill + gate evidence,
update skill promotion metadata, and prove the loop in the GUI harness. Do not
hand back after a plan, partial scaffold, or unvalidated implementation. Only
stop if blocked by missing credentials, missing native runtime capability, or an
explicit user instruction.

Non-negotiable target shape:
- Route contracts are the product primitive.
- Skills are bounded guidance, not authority.
- Workflows are the executable composition layer.
- Runtime owns route classification, phase gates, evidence, and policy.
- skill_context resolves from the runtime registry only.
- Production templates pin skills by hash once imported/promoted.
- Route evidence is visible in run details and GUI evidence surfaces.
- GUI workflows remain modular, componentized, buildable, forkable, saveable,
  validatable, runnable, and inspectable.
- GUI harness must prove create -> save -> validate -> run -> inspect -> fork
  -> evidence review.

Implementation order:
1. Read the current guide and relevant source files:
   - docs/plans/coding-route-skill-registry-master-guide.md
   - packages/agent-ide/src/runtime/workflow-node-registry.ts
   - packages/agent-ide/src/types/graph.ts
   - packages/agent-ide/src/runtime/workflow-harness-tools.ts
   - apps/autopilot/src-tauri/src/project/runtime.rs
   - apps/autopilot/src-tauri/src/project/commands.rs
   - apps/autopilot/src-tauri/src/project/templates.rs
   - apps/autopilot/src-tauri/src/project/validation.rs
   - apps/autopilot/src/services/TauriRuntime.ts
   - scripts/lib/autopilot-gui-harness-contract.mjs
   - scripts/lib/autopilot-gui-harness-validation/core.mjs
   - examples/agent-skills-main/README.md
2. Confirm the current green baseline still passes for skill_context and
   build/debug/review route proofs.
3. Harden route schemas:
   - RouteContract
   - RoutePhase
   - RouteGateResult
   - RouteSkillSelection
   - RouteRunSummary
4. Import examples/agent-skills-main as Draft through runtime skill source
   machinery with provenance. Do not scan skill folders during workflow
   execution.
5. Add phase tags and route tags for the first five skills:
   - incremental-implementation
   - test-driven-development
   - debugging-and-error-recovery
   - code-review-and-quality
   - source-driven-development
6. Add benchmark/retained verification tasks for those skills.
7. Emit promotion-loop evidence:
   - route id
   - phase id
   - selected skill hash
   - skill lifecycle state
   - benchmark result
   - gate result
   - confidence update
   - promotion/demotion/stale decision
   - evidence refs
8. Update skill registry metadata from benchmark evidence without broad
   promotion shortcuts.
9. Map phase-aware harness components to build/debug/review phases.
10. Improve GUI run details and evidence surfaces for route/phase/skill/gate
    and promotion-loop evidence.
11. Prove workflow forkability for route workflows and preserve route contracts,
    skill pins, gates, and evidence expectations across forks.
12. Add GUI harness contract and validation proof for the full promotion loop.
13. Run and fix until green:
    - cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml coding_route -- --nocapture
    - cargo test --manifest-path apps/autopilot/src-tauri/Cargo.toml workflow_skill_context -- --nocapture
    - npm run build:ide
    - npm run build --workspace=autopilot
    - npm run test:autopilot-gui-harness
    - npm run validate:autopilot-gui-harness
    - AUTOPILOT_LOCAL_GPU_DEV=1 npm run validate:autopilot-gui-harness:run -- --window-timeout-ms 300000

Slice discipline:
- Work in narrow vertical slices.
- After each slice, run the narrowest useful validation.
- Do not skip GUI validation at the end.
- If a validation command fails, debug root cause and rerun.
- Do not replace desired architecture with convenience shortcuts.
- Do not introduce hidden prompt wrappers as a substitute for route contracts.
- Do not let skills execute scripts directly.
- Do not scan arbitrary skill folders during workflow execution.
- Do not collapse skills, personas, and route templates into one object.
- Do not add ship route until the promotion loop is green.

Final response requirements:
- Summarize the promotion-capable route loop implemented.
- List changed files by area.
- List every validation command run and result.
- Link the latest GUI evidence result and promotion-loop proof artifact.
- Call out any remaining gap only if it is genuinely blocked.
```

## Summary

The desired end state is not "more skills" and not "a better prompt." It is a
promotion-capable typed coding route pipeline that uses skills as explicit,
receipt-backed context.

`agent-skills-main` is valuable because it has a mature lifecycle shape. The
runtime should absorb that shape into Draft registry entries, route phase tags,
benchmark-backed promotion records, workflow templates, and phase gates. The
registry remains the source of skill truth. `skill_context` remains the context
bridge. Coding routes remain the operator-visible process.

The current route substrate is green for build/debug/review. The next finish
line is the self-improving loop:

```text
route -> skill selection -> phase evidence -> gate -> benchmark
      -> promotion/demotion/stale decision -> GUI-visible proof
```

Once that loop is implemented and GUI-validated, this guide can be retired and
the team can confidently shift attention to broader agent harness opportunities.
That is the clean path from agent harness to verifiable coding-worker runtime:
flexible in chat, deterministic in harnesses, buildable and forkable in
Autopilot workflows, and improvable through retained evidence.
