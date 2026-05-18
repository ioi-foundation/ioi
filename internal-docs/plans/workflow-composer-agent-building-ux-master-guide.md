# Workflow Composer Agent-Building UX Master Guide

Owner: Autopilot / workflow compositor / runtime contracts / authority UX

Status: in progress

Created: 2026-05-17

Primary audit input:

- `internal-docs/audits/workflow-composer-live-agent-building-ux-frictions.md`

## Executive Verdict

The Workflow Composer has the right architectural bones and the core happy path
is already close: a user can add `Manual input`, search `model`, add an
`Agent Step`, search `inline output`, and receive an auto-connected graph.

The remaining UX gap is clarity at the moments where a user is deciding what to
do next. The product sometimes exposes runtime internals, compatibility
constraints, raw bridge exceptions, and global binding modals when it should
offer local repair actions, clear readiness blockers, and topology-first
composition.

The target is:

> A workflow author can build a useful agent without knowing IOI internals, while
> every visible choice still compiles to canonical runtime, authority, policy,
> receipt, and manifest truth.

This guide turns the live frictions into an implementation plan. It should be
used as the source of truth for the next Workflow Composer UX hardening pass
before broad Phase 5 connector expansion adds more palette and binding surface
area.

## Doctrine

- No second runtime.
- No React Flow shadow truth store.
- Daemon/runtime contracts remain source of truth.
- Wallet authority and runtime readiness are projected into the composer; they
  are not invented by the composer.
- Provider names, connector transport types, and plugin mechanics must not
  become workflow semantics.
- Advanced runtime details remain available, but default authoring surfaces use
  user-facing language.
- The canvas is for topology. Inspectors and modals are for configuration,
  evidence, receipts, and advanced details.
- Policy is not tracing. Readiness, policy, authority, receipts, and trace
  evidence remain distinct in the UI.

## UX North Star

Workflow composition should feel like building an autonomous system through a
small set of plain-language moves:

```text
start with input
-> add an agent step
-> bind model capability
-> attach tools or context
-> add verification and output
-> check readiness
-> run
-> inspect receipts
```

The user should never need to understand `model_call`, `plugin_tool`,
`runtimeContract`, `invoke`, port ids, or manifest sidecars before their first
successful workflow.

Best-in-class behavior for this product means:

- errors are actionable before they are technical;
- search understands ordinary authoring words;
- blocked states show repair actions next to the blocked object;
- common next steps are visible without opening unrelated global panels;
- configuration is progressive, not front-loaded;
- advanced/runtime details are one click away, not in the first line of copy;
- keyboard and pointer flows both preserve momentum;
- every simplification has a deterministic runtime mapping.

## Completion Dashboard

| Slice | Goal | Status | Done when |
| --- | --- | --- | --- |
| Runtime-unavailable error normalization | Remove raw bridge exceptions from Validate, Run, and catalogs. | Done / regression guarded | No visible `Cannot read properties...invoke`; blockers show remedies and advanced details. |
| Selected-node repair actions | Make model/tool/output/eval repairs local to the selected node. | Planned | Agent Step and Tool Pack nodes expose contextual repair CTAs and deep-link global modals. |
| Compatible search recovery | Avoid dead-end empty states when global matches exist. | Planned | Searching `repo` after Manual input offers all matches, Add Agent Step, or clear compatible filter. |
| Topology-first add mode | Stop interrupting composition with full config modals. | Planned | Context/state/tool nodes add, select, and show next actions without dumping advanced JSON. |
| Search ranking and aliases | Rank ordinary intent queries by likely authoring intent. | Planned | Snapshot tests cover `repo`, `github`, `pr`, `browser`, `computer`, `model`, `output`. |
| Beginner inspector summary | Replace raw field counts with lifecycle/readiness summary. | Planned | Default bottom shelf shows readiness checklist; raw fields live under Advanced. |
| Tool family labeling | Hide plugin/transport labels from default authoring copy. | Planned | Default labels say Browser tool, Computer tool, Coding tool pack, MCP tool, Workflow tool. |
| Guided next rail | Offer non-blocking next steps after each common node add. | Planned | Prompt, tool, repo, and output flows can continue without palette hunting. |
| GUI regression net | Preserve behavior with live Playwright probes. | Planned | Prompt-agent, tool-agent, repo-agent, modal keyboard, search, and run-readiness probes pass. |

## Friction-To-Solution Map

### F1. Runtime Bridge Exceptions Leak Into Readiness

Observed:

- Validate surfaced `Workflow Bundle Unavailable` plus
  `Cannot read properties of undefined (reading 'invoke')`.
- Connector catalog fallback surfaced both tool and connector catalog `invoke`
  exceptions.

Target solution:

- Introduce a normalized user-facing blocker shape for runtime bridge and saved
  bundle availability failures.
- Keep technical exception details behind an `Advanced details` disclosure.
- Give concrete remedies:
  - `Save workflow`;
  - `Retry runtime bridge`;
  - `Open diagnostics`;
  - `Use offline presets`;
  - `Continue in desktop shell` when the web context lacks bridge access.

Suggested blocker copy:

```text
Runtime bridge unavailable
The composer could not reach the desktop/runtime bridge needed to read saved
workflow bundles or live catalogs.

Try saving the workflow, retrying the runtime bridge, or opening diagnostics.
Offline presets are available for draft composition.
```

Implementation notes:

- Normalize errors near the existing workflow bundle paths in
  `packages/agent-ide/src/WorkflowComposer/controller.tsx`.
- Apply the same normalizer to model catalog and connector/tool catalog modal
  fallbacks in `WorkflowComposerModals.tsx`.
- Do not swallow the original error. Store it in technical details, telemetry,
  run diagnostics, or advanced receipt payloads.

Regression guards:

- Validate prompt-agent graph in web/dev shell and assert no raw JS exception is
  visible.
- Open model and connector binding modals with bridge unavailable and assert
  user-facing fallback copy.

### F2. Capability Binding Repair Is Too Global

Observed:

- Agent Step had model capability/readiness hints, but the main repair path was
  the global `Bind Models` header action.
- The binding modal listed abstract rows like reasoning, vision, embedding, and
  image rather than focusing the selected node's problem.

Target solution:

- Add selected-node repair CTAs in the right rail and bottom shelf.
- When a selected node has a blocker, global `Bind Models` or `Bind Connectors`
  should open focused on that selected node or selected capability role.

Repair actions by node family:

| Node family | Primary local actions |
| --- | --- |
| Agent Step | Bind model capability, choose route, inspect authority, add output, add eval |
| Tool Pack | Bind tool capability, inspect credential posture, attach to agent, add verifier |
| Context/Repository | Connect to agent, add branch policy, add PR/review path |
| Output | Validate output, add eval, run |
| Verification | Add output, run tests, inspect evidence |

Best-in-class behavior:

- The repair action appears where the user is already looking.
- The global binding modal remains available for expert batch editing.
- The selected-node path deep-links to one row and one fix.

Implementation notes:

- Add a `WorkflowRepairAction` view model derived from selected node,
  readiness, binding metadata, and lifecycle readiness.
- Expose repair actions through:
  - selected node bottom shelf;
  - right rail readiness panel;
  - canvas node status pill tooltip;
  - optional command palette entries.
- Keep all actions as projections of daemon/runtime readiness and authority.

Regression guards:

- Select Agent Step and assert `Bind model capability` is visible.
- Click it and assert the model binding modal focuses the selected node or role.
- Select Browser Use and assert `Bind tool capability` is visible.

### F3. Compatible Search Can Hide The User's Intent

Observed:

- Before selecting a starter, `repo` returned relevant primitives.
- After selecting `Manual input`, compatible search returned a generic empty
  state for `repo`, `repository`, `github`, and `branch`.

Target solution:

- Search should distinguish:
  - matches compatible with the selected node;
  - matches available globally;
  - recommended bridge steps to make the desired primitive compatible.

Empty state target:

```text
No repo primitives connect directly from Manual input.

Show all repo primitives, add an Agent Step first, or clear the compatible
filter.
```

Actions:

- `Show all repo matches`;
- `Add Agent Step`;
- `Clear compatible filter`;
- `Explain why` with port compatibility detail.

Implementation notes:

- Compute global search matches alongside compatible matches.
- If compatible matches are empty but global matches exist, render a
  `workflow-compatible-empty-with-global-matches` state.
- Use known bridge recommendations:
  - source/input -> Agent Step -> repo/PR tools;
  - source/input -> Tool Pack for direct utility tools;
  - context -> Agent Step for reasoning;
  - Agent Step -> Output for materialization.

Regression guards:

- With Manual input selected, search `repo`; assert no generic empty state.
- Assert `Show all repo matches` and `Add Agent Step` are visible.
- Assert clicking `Show all repo matches` switches to all/global results without
  losing the search query.

### F4. Full Config Modals Interrupt Topology Building

Observed:

- Adding `GitHub Context` opened the node config modal immediately.
- The modal showed advanced runtime identity JSON before the user had built a
  workflow topology.

Target solution:

- Default add behavior should be topology-first:
  - add node;
  - select node;
  - show lightweight next actions;
  - show required configuration only when required to make the node meaningful.
- Full config opens only when:
  - the user explicitly clicks `Configure`;
  - required fields block even draft topology;
  - the primitive is a form-like input that cannot be placed without values.

Implementation notes:

- Revisit `handleAddNodeFromLibrary(... openConfig: true ...)` calls from the
  drawer.
- Add creator metadata such as `defaultAddMode`:
  - `topology_first`;
  - `quick_required_config`;
  - `open_config`;
  - `advanced_only`.
- Context, repository, GitHub, PR, branch, tool, and output primitives should
  usually be `topology_first`.

Regression guards:

- Add Repository Context from blank drawer and assert no config modal opens.
- Add GitHub Context from blank drawer and assert no advanced summary JSON is
  visible by default.
- Verify `Configure node` still opens the full modal.

### F5. Tool Identity Is Still Plugin-Shaped

Observed:

- Search labels Browser Use as `Tool Pack` and `Plugin`.
- Connector modal says connector/plugin even for native computer-use style
  tools.

Target solution:

- Default authoring language should use capability family names:
  - Browser tool;
  - Computer tool;
  - Coding tool pack;
  - MCP tool;
  - Workflow tool;
  - Repository tool.
- Advanced surfaces can show `plugin_tool`, `mcp_tool`, `tool-capability:*`,
  transport, and adapter ids.

Implementation notes:

- Keep canonical node kind and runtime contract unchanged.
- Add `authoringFamilyLabel` or equivalent to node creator metadata.
- Let the drawer, card subtitle, selected-node summary, and right rail prefer
  authoring labels.
- Keep exact capability refs in advanced/runtime/receipt sections.

Regression guards:

- Search `browser`; assert first result reads as Browser tool in default mode.
- Advanced palette still exposes raw runtime kind and capability metadata.

### F6. Bottom Shelf Over-Indexes On Raw Field Counts

Observed:

- Agent Step summary says `14 configured fields modelRef, modelCapabilityRef...`.
- The useful beginner question is not "how many fields exist?" It is "what is
  ready, what is missing, and what should I do next?"

Target solution:

- Default selected-node summary becomes lifecycle/readiness oriented.
- Raw field counts move to Advanced.

Suggested Agent Step summary:

```text
Input connected
Model capability: local-first route
Tools: none attached
Output: missing
Receipts: required
Tests: none
Ready: blocked by output
```

Implementation notes:

- Add a `WorkflowNodeAuthoringSummary` projection.
- Source it from node config, binding readiness, local graph topology,
  lifecycle readiness, and validation issues.
- Render in `WorkflowBottomShelf.tsx` and right rail selected-node panels.

Regression guards:

- Select Agent Step and assert raw field-list text is not in default summary.
- Open Advanced and assert raw fields and primitive projection remain available.

### F7. Modal Close And Keyboard Flow Need Consistency

Observed:

- Visible `Close` and `Done` buttons worked.
- `Escape` did not reliably close one model binding modal pass, causing
  subsequent canvas clicks to be intercepted.

Target solution:

- Non-destructive modals close on Escape.
- Destructive or unsaved modals show a confirm state before closing.
- After closing, focus returns to the action that opened the modal or to the
  selected node's next action.

Implementation notes:

- Audit modal components in `WorkflowComposerModals.tsx` and
  `WorkflowNodeConfigModal.tsx`.
- Standardize modal keyboard handling.
- Add focus restoration.

Regression guards:

- Open model binding, connector binding, and node config modals.
- Press Escape.
- Assert modal closes or presents an explicit unsaved-change confirmation.
- Assert `Add next node` is clickable after modal close.

### F8. Search Ranking Can Prefer Adjacent Concepts

Observed:

- `repo` ranked `GitHub Context` above `Repository Context`.
- A safer local repository primitive should usually be the first result for a
  generic repo query.

Target solution:

- Add query-specific alias and ranking boosts for ordinary authoring intent.

Expected top results:

| Query | Top results |
| --- | --- |
| `repo` | Repository Context, Coding tool pack, Git diff, GitHub Context, Branch Policy |
| `repository` | Repository Context, GitHub Context, Branch Policy, PR Attempt |
| `git` | Repository Context, Git diff, Coding tool pack, GitHub Context |
| `github` | GitHub Context, Issue Context, PR Attempt, Pull Request, Review Gate |
| `pr` | PR Attempt, Pull Request, Review Gate, Branch Policy |
| `pull request` | PR Attempt, Pull Request, Review Gate, Branch Policy |
| `browser` | Browser tool, Browser/computer tool, Computer tool |
| `computer` | Computer tool, Browser/computer tool, Sandboxed Computer, Browser tool |
| `model` | Agent Step, Vision model, Embedding model, Evaluator |
| `output` | Inline output, File output, Delivery draft, Deploy target, Media output |

Implementation notes:

- Keep deterministic ranking.
- Avoid hiding advanced matches. Re-rank, do not remove.
- Add tests close to the node library search/filter code.

Regression guards:

- Snapshot top five search results for each query above in default, all, and
  advanced modes where relevant.

## Best-In-Class UX Patterns To Adopt

### Progressive Disclosure

Default view:

- what the node does;
- whether it is ready;
- what it needs next;
- what it will produce.

Advanced view:

- runtime node kind;
- contract id;
- capability ref;
- route id;
- port ids;
- raw manifests;
- receipt payloads;
- projection JSON.

### Local Repair Before Global Configuration

Every blocker should appear with a local repair action. Global binding and
settings modals remain for batch edits, but first-run authoring should be
object-centered:

```text
selected node -> blocker -> repair action -> focused editor -> readiness update
```

### Topology First, Values Second

The user should be able to sketch a graph before filling every field. Required
values should appear as readable blockers, not as a wall of config.

### Search As Intent Translation

Search should accept words a user would say:

- repo;
- PR;
- browser;
- computer;
- scrape;
- summarize;
- approve;
- verify;
- draft;
- publish;
- memory;
- skill;
- eval;
- output.

The drawer should translate those words into canonical primitives without
making the user learn internal taxonomy first.

### Fail Closed With Help

When the runtime cannot proceed, the UI should explain:

- what is blocked;
- why it is blocked;
- whether the graph, authority, runtime bridge, policy, credential, eval, or
  output is missing;
- what action can repair it;
- where technical detail lives.

### Keep The User In Flow

Avoid modal traps during common graph-building:

- add node;
- add next node;
- attach tool;
- bind capability;
- add output;
- validate.

Configuration modals should be focused, closable, keyboard-safe, and followed
by clear continuation actions.

## Canonical UI Components

### Readiness Blocker Card

Fields:

- `title`;
- `plain_language_summary`;
- `readiness_domain`: run, authority, package, eval, deploy, promotion,
  runtime bridge, catalog, policy;
- `blocked_object_ref`;
- `repair_actions`;
- `advanced_detail_ref`.

### Repair Action Button

Fields:

- `label`;
- `target_node_id`;
- `action_kind`;
- `opens_surface`: modal, rail, drawer, diagnostics, command palette;
- `focus_ref`;
- `requires_authority`;
- `dry_run_safe`.

### Compatible Search Recovery State

Fields:

- `query`;
- `selected_node_ref`;
- `compatible_count`;
- `global_count`;
- `recommended_bridge_action`;
- `show_all_action`;
- `clear_filter_action`;
- `technical_port_explanation`.

### Authoring Summary

Fields:

- `plain_label`;
- `role_in_graph`;
- `input_status`;
- `capability_status`;
- `authority_status`;
- `tool_status`;
- `output_status`;
- `eval_status`;
- `receipt_status`;
- `next_actions`;
- `advanced_projection_ref`.

### Guided Next Rail

Fields:

- selected node ref;
- graph state;
- suggested next primitives;
- repair actions;
- readiness action;
- last action result.

## Implementation Plan

### Slice 1: Normalize Runtime-Unavailable Errors

Goal: no raw JS bridge/catalog exceptions in user-facing readiness.

Tasks:

1. Add a helper that maps known runtime bridge, catalog, and saved bundle
   failures into structured composer blockers.
2. Use it in Validate, Run, model binding catalog, and connector binding
   catalog paths.
3. Add advanced details disclosure for original error text.
4. Add tests and Playwright probe.

Acceptance:

- Validate and Run never show `Cannot read properties of undefined`.
- Connector/model modal fallbacks describe offline presets or runtime bridge
  unavailability in plain language.
- Original technical detail remains available in Advanced.

### Slice 2: Selected-Node Repair Actions

Goal: blocked nodes explain and repair themselves.

Tasks:

1. Create selected-node repair action projection.
2. Render repair actions in bottom shelf and right rail.
3. Wire `Bind model capability` and `Bind tool capability` to focused modals.
4. Add output/eval/readiness quick actions.

Acceptance:

- Selecting Agent Step shows local model binding and output actions.
- Selecting Browser Use shows local tool binding action.
- Header binding buttons deep-link when a relevant node is selected.

### Slice 3: Compatible Search Recovery

Goal: search never dead-ends when global matches exist.

Tasks:

1. Compute global matches while compatible filtering is active.
2. Render compatibility-aware empty state.
3. Add `Show all matches`, `Add Agent Step`, and `Clear compatible filter`.
4. Preserve query across mode/filter changes.

Acceptance:

- With Manual input selected, searching `repo` shows global/recovery guidance.
- The user can move from that state to a viable repo-agent topology.

### Slice 4: Topology-First Add Mode

Goal: adding a primitive does not interrupt topology composition unless required.

Tasks:

1. Add node creator metadata for default add behavior.
2. Change drawer adds for context/state/tool/output primitives to topology-first.
3. Keep explicit `Configure node` available.
4. Keep required config prompts for nodes that truly cannot be placed.

Acceptance:

- Adding Repository Context does not open advanced config by default.
- Adding GitHub Context does not show projection JSON by default.
- Users can continue adding next nodes immediately.

### Slice 5: Search Ranking And Authoring Labels

Goal: ordinary queries return likely primitives first, with user-facing labels.

Tasks:

1. Add alias/ranking metadata for target queries.
2. Add authoring family labels for tool-capability primitives.
3. Update drawer result labels and subtitles.
4. Add snapshot tests.

Acceptance:

- Query top-result table in this guide passes.
- Default labels avoid `plugin_tool` and transport jargon.
- Advanced palette still exposes runtime kind and contract details.

### Slice 6: Beginner Inspector Summary

Goal: bottom shelf answers "what is ready and what next?"

Tasks:

1. Add authoring summary projection.
2. Render lifecycle summary before raw configuration field counts.
3. Move raw fields/projection JSON into Advanced.
4. Add tests for Agent Step, Tool Pack, Repository Context, and Output.

Acceptance:

- Agent Step summary shows input, capability, tools, output, receipts, tests,
  and readiness.
- Raw field list is absent from default view and present in Advanced.

### Slice 7: Guided Next Rail

Goal: common graph-building flows can continue without palette hunting.

Tasks:

1. Add non-blocking next-step rail/cards after node add.
2. Drive suggestions from graph topology and compatibility hints.
3. Include repair actions and next primitive suggestions.
4. Add Playwright probes for prompt-agent, tool-agent, and repo-agent flows.

Acceptance:

- After adding Manual input, the user sees Add Agent Step.
- After adding Agent Step, the user sees Bind model, Attach tool, Add output.
- After adding Output, the user sees Validate, Add eval, Run.

### Slice 8: Modal Keyboard And Focus Polish

Goal: modals do not trap composition flow.

Tasks:

1. Standardize Escape behavior for non-destructive modals.
2. Add focus restoration.
3. Add explicit continue actions after modal completion.
4. Add keyboard tests.

Acceptance:

- Escape closes model binding, connector binding, and node config modals when no
  destructive unsaved change exists.
- Focus returns to the initiating action or selected-node repair action.
- `Add next node` remains clickable after close.

### Slice 9: Full GUI Regression Net

Goal: protect the UX from regressing as Phase 5 adds connectors.

Required probes:

- prompt-agent graph creation;
- browser-tool attachment;
- repo-agent discovery and recovery;
- selected-node model binding repair;
- connector binding fallback;
- Validate/Run fail-closed copy;
- modal Escape behavior;
- search ranking snapshots;
- default vs advanced label visibility.

Acceptance:

- All probes pass against a fresh dev app.
- Generated screenshots/logs stay outside git or under ignored evidence paths.

## Validation Plan

Run targeted static/unit tests after each slice:

```text
npm test -- --run workflow
npm test -- --run WorkflowComposer
npm test -- --run workflow-node
```

Run GUI probes after UX slices:

```text
npm run dev:desktop
node <probe for prompt-agent>
node <probe for tool-agent>
node <probe for repo-agent>
```

Final manual clickthrough:

1. Open Workflows.
2. Build Manual input -> Agent Step -> Inline output.
3. Validate and Run.
4. Build Manual input -> Agent Step -> Browser tool -> Inline output.
5. Search `repo` from blank and compatible states.
6. Add Repository Context and continue composing without forced advanced modal.
7. Bind model/tool capability through selected-node repair actions.
8. Confirm advanced runtime details remain available.

## Definition Of Done

- Raw bridge/catalog JS exceptions do not appear in default UI.
- Agent Step and Tool Pack blockers show local repair actions.
- Compatible search never shows a generic empty state when global matches exist.
- Repository/GitHub/context nodes do not interrupt topology-first composition
  with advanced config by default.
- Search ranking matches ordinary user intent for repo, git, GitHub, PR,
  browser, computer, model, and output queries.
- Default labels use authoring concepts; advanced mode preserves runtime terms.
- Bottom shelf and right rail show lifecycle-aware summaries before raw fields.
- Keyboard modal flow is reliable.
- Prompt-agent, tool-agent, and repo-agent Playwright probes pass.
- No React Flow shadow runtime truth is introduced.

## Non-Goals

- Do not redesign the entire Workflow Composer visual system in this pass.
- Do not remove advanced/debug/runtime details.
- Do not create provider-specific workflow semantics.
- Do not turn the guided next rail into a wizard that blocks freeform graph
  editing.
- Do not expand connector breadth until this pass is complete enough that new
  connector primitives inherit the clarified authoring model.

## Open Questions

- Should topology-first add mode be the default for every node family except
  required-value sources, or should each creator define it explicitly?
- Should `repo` prefer local Repository Context even when GitHub Context has a
  stronger exact metadata hit?
- Should selected-node repair actions live primarily in the right rail, bottom
  shelf, or both?
- Should the composer have a persistent "Beginner / Advanced" toggle, or should
  progressive disclosure be local to each panel?
- Should failed runtime bridge/catalog lookups create durable diagnostic
  receipts, or only transient UI blockers?

## Source Notes

- Live audit: `internal-docs/audits/workflow-composer-live-agent-building-ux-frictions.md`
- Primary UI files discovered during audit:
  - `packages/agent-ide/src/WorkflowComposer/controller.tsx`
  - `packages/agent-ide/src/WorkflowComposer/view.tsx`
  - `packages/agent-ide/src/WorkflowComposer/support.tsx`
  - `packages/agent-ide/src/features/Workflows/WorkflowComposerModals.tsx`
  - `packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx`
  - `packages/agent-ide/src/features/Workflows/WorkflowNodeConfigModal.tsx`
- Live evidence logs were kept outside git under `/tmp/workflow-composer-clickthrough-*.json`.
