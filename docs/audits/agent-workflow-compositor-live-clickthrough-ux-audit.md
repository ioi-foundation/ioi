# Agent Workflow Compositor Live Clickthrough UX Audit

Status: live GUI audit for next implementation leg
Created: 2026-05-14
Scope: Autopilot Workflows / React Flow composer user path
Companion: `docs/audits/agent-workflow-compositor-primitive-taxonomy-ux-audit.md`

## Goal

Audit the workflow compositor as a user trying to compose an agent workflow, and
identify where taxonomy, shape profiles, search, configuration, and UI affordances
feel arbitrary, overly internal, or non-intuitive.

This audit is intentionally separate from the static primitive taxonomy audit.
It records what the running GUI actually communicated during a clickthrough.

## Method

Environment:

- ran Autopilot at `http://127.0.0.1:5173/`;
- used a temporary Playwright Chromium install outside the repo;
- screenshots and probe logs were written to `/tmp/ioi-compositor-ux-audit/`;
- generated evidence was not committed.

Click path:

1. Opened Autopilot from a fresh GUI session.
2. Skipped onboarding.
3. Opened `Workflows` from the activity bar.
4. Clicked the empty-canvas primitive browser.
5. Searched for expected workflow concepts: `skill`, `hook`, `repo`,
   `github`, `pr`, `approval`, `model`, `memory`, `worker`, `terminal`,
   `policy`, and `output`.
6. Added `Manual trigger`.
7. Inspected the node configuration modal and compatible-next suggestions.
8. Opened the default harness graph.
9. Tried the composer `Run` button from a blank draft workflow.

Primary evidence files:

- `/tmp/ioi-compositor-ux-audit/live-clickthrough-detail.json`
- `/tmp/ioi-compositor-ux-audit/live-01-workflows-empty.png`
- `/tmp/ioi-compositor-ux-audit/live-02-drawer-open.png`
- `/tmp/ioi-compositor-ux-audit/live-04-after-manual-trigger.png`
- `/tmp/ioi-compositor-ux-audit/live-07-after-harness.png`
- `/tmp/ioi-compositor-ux-audit/after-run.png`

## Executive Findings

The runtime-backed compositor is powerful and visibly connected to real IOI
contracts, but the authoring experience still exposes too many implementation
facets as first-class choices. A user trying to compose an agent workflow has to
translate between runtime terms, node registry terms, macro helpers, searchable
concepts, shape badges, and inspector panels.

The strongest product direction remains:

> expose a small default palette of durable agent/workflow primitives, and move
> implementation facets into typed config, ports, inspectors, receipts, and an
> advanced/debug palette.

## P0 Finding: Blank Composer Run Crashes The App

Reproduction:

1. Open `Workflows`.
2. Leave the draft graph blank.
3. Click `Run`.

Observed:

- the UI navigated away from the composer to a Chat render failure;
- the screen displayed `CHAT RENDER BLOCKED`;
- error: `Cannot read properties of undefined (reading 'transformCallback')`;
- stack included `src/windows/ChatShellWindow/hooks/useChatPlaybookRuns.ts:157`.

Expected:

- composer should stay in the workflow surface;
- blank or invalid workflows should fail closed with a validation/readiness
  explanation;
- no route-level render failure should occur;
- run history should either not mutate or should record a blocked/invalid
  attempt with durable evidence.

Recommendation:

1. Guard `Run` in the composer when the workflow has no runnable activation
   manifest.
2. Harden `useChatPlaybookRuns` against an absent transform callback.
3. Add a Playwright regression: blank workflow -> click real `Run` button ->
   assert no render-blocked page and a visible validation/blocking message.

## Palette And Search Findings

The empty composer exposes `115` primitives across `12` groups:

| Group | Count |
| --- | ---: |
| Start | 4 |
| Sources | 5 |
| Transform | 5 |
| AI | 10 |
| Tools | 14 |
| Connectors | 6 |
| Flow | 18 |
| State | 41 |
| Human | 2 |
| Outputs | 7 |
| Tests | 2 |
| Proposals | 1 |

This is runtime-complete, but not authoring-simple. The largest friction is that
many entries are runtime operations, subsystem status rows, or lifecycle facets
rather than things a workflow author naturally reaches for.

Search observations:

| Query | Observed result | UX implication |
| --- | --- | --- |
| `skill` | `Discover skills`, `Pinned skill`, `Skill`, `Skill Pack` | Skills are split across several nearly equivalent concepts. |
| `hook` | `Webhook/API payload`, `Hook`, `Hook Policy` | Hook search mixes event input and governed hook configuration. |
| `repo` | `GitHub Context`, `Repository Context` | Reasonable, but repo/issue/PR flow is spread across multiple nouns. |
| `github` | context, issue, PR attempt, PR create | Good coverage, but PR authoring shape is not yet obvious. |
| `pr` | 52 primitives | Search is too broad and drowns the expected Pull Request concepts. |
| `approval` | 16 primitives | Useful but blends gates, policy internals, packages, connectors, and outputs. |
| `model` | model variants plus `Model Binding` | Missing the user-facing `Agent Step` concept. |
| `memory` | 38 primitives | Matches port metadata too aggressively; memory operation nodes are buried. |
| `worker` | 0 primitives | User concept does not map to visible labels; subagent terms are hidden under State. |
| `terminal` | 0 primitives | The terminal coding-loop macro exists but disappears during search. |
| `policy` | context, memory, branch, hook policies | Concept is present but not organized as one gate/config family. |
| `output` | 14 primitives including non-output nodes | Search results mix semantic outputs and nodes that merely have output ports. |

Recommendation:

- add a default/advanced palette split;
- index composition helpers in search;
- add synonym metadata: `worker -> subagent`, `terminal -> coding loop`,
  `agent -> model/agent step`, `repo -> repository`, `pull request -> PR`;
- rank label/name matches above port/config metadata matches;
- collapse skill, memory, worker, tool, and hook facets into canonical default
  primitives with modes.

## Empty Canvas Findings

What works:

- the prompt `What starts this workflow?` is approachable;
- trigger/input starter cards are better than opening directly into a giant
  drawer;
- metadata badges expose readiness without needing to run validation first.

Friction:

- the right rail defaults to `Outputs` and says `No output nodes configured`,
  while the center overlay says to start with a trigger or input;
- the starter metadata `Start · no binding · none · no schema · Ready` is
  implementation-dense for a first action;
- there is no guided path for "build a coding agent workflow" from the blank
  canvas besides knowing to choose a macro or browse primitives.

Recommendation:

1. Make the empty-state right rail mirror the current task: `Start`.
2. De-emphasize binding/schema/status metadata until hover or details.
3. Offer three high-level starters:
   `Agent workflow`, `Tool workflow`, `Verification workflow`.
4. Keep raw trigger/input cards available under `Start from scratch`.

## Add Node Drawer Findings

What works:

- the drawer has real search, groups, counts, and recent primitives;
- composition helpers are prominent;
- compatible-node suggestions appear after a node is selected.

Friction:

- there are two visible `Add` entry points with different placement and the same
  accessible name pattern;
- composition helpers are visually listed before the primitive library, but
  search ignores them;
- the default drawer mixes beginner primitives with protocol/debug operations;
- group names such as `Flow`, `State`, and `AI` become overloaded because they
  contain unrelated runtime subsystems.

Recommendation:

- rename the main action to `Add node`;
- rename the canvas toolbar action to `Open palette`;
- split drawer tabs into `Recommended`, `All`, and `Advanced`;
- keep `Composition helpers` searchable and optionally pin them to the
  recommended tab;
- replace overloaded groups with the canonical taxonomy from the static audit.

## Node Configuration Findings

After selecting `Manual trigger`, the app opens a blocking `Node configuration`
modal. The modal is technically rich, but it interrupts the composition loop.
The user must close or submit it before adding downstream nodes.

Observed modal sections include:

- settings;
- connections;
- inputs/outputs;
- schema references;
- run data;
- tests;
- advanced config.

Good signal:

- compatible primitives were discoverable inside the modal:
  `Discover skills`, model variants, `Pinned skill`, connector read/write.

Friction:

- the default modal lands a new user inside configuration density before the
  graph has meaningful shape;
- the primary next action is not "add compatible next node";
- the compatible suggestions are locked inside the modal while the Add button
  behind it is blocked;
- the trigger config shows schedule/event fields even for a manual trigger,
  which makes the primitive shape feel arbitrary.

Recommendation:

1. Use a right-side inspector by default for first-run node configuration.
2. Add a primary `Add next node` action that opens compatible suggestions.
3. Hide irrelevant config fields by mode.
4. Keep the full modal as `Advanced configuration`.

## Default Harness Findings

Clicking `Harness` opens the `Default Agent Harness` as a read-only graph.
This is useful proof that the system has a real canonical harness, but it is
not yet a clean teaching artifact.

Observed:

- graph opens read-only and blocked;
- right rail defaults to `Settings`;
- canvas starts zoomed into partial group cards and scattered nodes;
- a floating legend lists many internal node types:
  `runtime_task`, `runtime_job`, `runtime_checklist`, `workflow_package_export`,
  `workflow_package_import`, `pr_attempt`, `github_pr_create`, `hook_policy`,
  `gui_harness_validation`, and more.

Friction:

- the graph reads as an implementation proof more than an authoring template;
- the read-only/block state is accurate but intimidating;
- the default viewport does not present the full topology or a clear first
  path through it;
- internal type names dominate the visual legend.

Recommendation:

- open the harness in a fitted overview with group-level labels;
- show a `Use as template` / `Fork editable copy` call to action;
- default to collapsed canonical groups: input, context, skills, memory, tools,
  agent step, policy, verification, recovery, output;
- move internal type-count legend into the advanced/runtime inspector.

## Naming And Shape Profile Findings

Several labels expose implementation boundaries that matter to IOI but are not
the user's authoring language:

| Current visible label | Better default concept |
| --- | --- |
| `Model`, `Model Binding`, `Evaluator` | `Agent Step` with model route/config |
| `Skill`, `Skill Pack`, `Discover skills`, `Pinned skill` | `Skills` with discovery/pin/import modes |
| `Hook`, `Hook Policy` | `Hook` with policy section; `Policy Gate` only when blocking |
| `Subagent pool`, `Spawn subagent`, `Join subagent` | `Worker` with lifecycle mode |
| `Memory search/list/remember/edit/delete/status/policy` | `Memory` with operation mode |
| `GitHub Context`, `Issue Context`, `PR Attempt`, `GitHub PR Create` | `Repository`, `Pull Request`, `Review Gate` |
| `Runtime Task`, `Runtime Job`, `Runtime Checklist` | advanced runtime/run-state projection |

Shape recommendation:

- use shape/color to distinguish execution boundaries, not registry families;
- expose text equivalents for status colors and icons;
- reserve advanced badges for runtime ids, receipt counts, policy refs, and
  replay data.

## Suggested Implementation Slices

1. **Run crash guard**
   Fix the blank composer `Run` crash and add the regression test first. This is
   a trust issue in the authoring loop.

2. **Search and synonym hardening**
   Index macros, add synonym metadata, rank label matches above port/config
   matches, and add coverage for `worker`, `terminal`, `agent`, and `pull
   request`.

3. **Default vs advanced palette**
   Add palette visibility metadata and hide runtime/debug facets from the
   default drawer without removing the underlying runtime nodes.

4. **Canonical primitive labels**
   Introduce user-facing labels for the default palette while preserving
   canonical node ids and runtime contracts in advanced inspector tabs.

5. **Post-starter composition flow**
   After adding a trigger/input, prefer a side inspector and surface `Add next
   node` compatible suggestions instead of immediately opening a dense modal.

6. **Harness teaching view**
   Make `Harness` open to a fitted canonical-group overview with a clear fork/use
   action and move raw type counts into advanced details.

## Definition Of Done For The Next Leg

- Default palette exposes canonical authoring primitives, not every runtime
  facet.
- Advanced palette and inspectors still expose every runtime contract needed for
  protocol/debug users.
- Search returns the expected primitive for common authoring words.
- Composition helpers are searchable and can be inserted without knowing their
  exact drawer position.
- Adding a starter node naturally presents compatible next actions.
- Blank or invalid runs never navigate to a render-blocked surface.
- The default harness teaches the desired workflow topology before exposing raw
  runtime internals.
