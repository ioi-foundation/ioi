# Workflow Composer Live Agent-Building UX Frictions

Date reviewed: 2026-05-17

## Purpose

This is a living audit of the Workflow Composer from the perspective of a user who does not know the IOI runtime architecture by memory. The goal is to click through real composition paths, try to build plausible agent workflows, and record where the surface feels obtuse, arbitrary, over-internal, or under-guided.

This document is intentionally practical. It should preserve observations, exact click paths, friction points, and proposed product fixes so the next implementation slice can continue after context compaction.

## Audit Method

- Use the running Hypervisor desktop/web dev surface at `http://127.0.0.1:1428/chat`.
- Navigate as a user through the real activity bar and Workflow Composer controls.
- Try multiple workflow shapes:
  - simple prompt-to-agent-to-output workflow;
  - coding/repo agent workflow;
  - tool-using workflow;
  - harness/topology exploration workflow.
- Prefer real clickthroughs over source-only inference.
- Record UI frictions separately from proposed implementation fixes.

## Executive Findings

The core composition loop is close. A user can start from `Manual input`, search `model`, add an `Agent Step`, search `inline output`, and get an auto-connected three-node graph without needing to know node ids, ports, or runtime manifests.

The main friction is not the existence of primitives. It is the amount of runtime-internal language exposed at the exact moments where a new user needs next-step guidance. Examples observed live:

- Validation and connector catalog fallback leak `Cannot read properties of undefined (reading 'invoke')`.
- Agent Step selection says `Capability: model-capability:route.local-first` while the node body also says `Model missing`, and the binding modal shows abstract binding rows rather than the selected node's next repair action.
- `repo` search is discoverable before a starter is selected, but after adding `Manual input`, the default compatible filter hides repository/GitHub/PR primitives and shows a dead-end empty state.
- Adding some non-starter primitives, such as `GitHub Context`, immediately opens a full config modal with raw advanced runtime identity, interrupting the composition flow.
- Tool attachment can work: `Browser Use` attached to a model and the connector modal projected capability, mode, credential, and approval posture. The same modal still showed catalog fallback exceptions.

## Clickthrough Log

Evidence was captured as local Playwright JSON logs outside git:

- `/tmp/workflow-composer-clickthrough-prompt-agent.json`
- `/tmp/workflow-composer-clickthrough-search-run.json`
- `/tmp/workflow-composer-clickthrough-bind-tool.json`
- `/tmp/workflow-composer-clickthrough-browser-tool.json`
- `/tmp/workflow-composer-clickthrough-repo-agent.json`

### Prompt Agent

Path:

1. Open Hypervisor at `http://127.0.0.1:1428/chat`.
2. Click `Workflows`.
3. Click the `Manual input` starter.
4. Click `Add next node`.
5. Search `model`.
6. Add `Agent Step`.
7. Search `inline output`.
8. Add `Inline output`.
9. Click `Validate`, then `Run`.

Observed:

- `Manual input` was added as a source node and selected.
- `Agent Step` auto-connected after `Manual input`.
- `Inline output` auto-connected after `Agent Step`.
- The status line accurately reported `Model added and connected after Manual input` and `Inline output added and connected after Model`.
- Validation blocked with `Workflow Bundle Unavailable` and the raw detail `Cannot read properties of undefined (reading 'invoke')`.
- Run on a graph missing an output produced better copy: `Run needs at least one output node before activation`.

### Search And Palette

Unselected drawer search was generally strong:

- `repo` returned GitHub Context, PR Attempt, GitHub PR Create, Review Gate, Branch Policy, Repository Context, Issue Context, and Runtime Doctor.
- `repository` returned Repository Context first.
- `git`, `github`, `pr`, `pull request`, `review`, and `branch` all returned plausible primitives.
- `browser` returned Browser Use and Browser/computer tool.
- `computer` returned Computer Use, Browser Use, Sandboxed Computer, and Browser/computer tool.
- `model` returned model-family Agent Step variants.
- `output` returned output primitives first, then broader output-related items.

After selecting `Manual input`, the compatible filter created blind spots:

- `repo`, `repository`, `github`, and `branch` returned no compatible primitives, even though the same concepts are available in the full palette.
- `git` returned Git diff and Coding tool pack.
- `pr` returned Proposal, not PR attempt/create.
- `pull request` returned Proposal, Invoke MCP tool, and a coding-budget helper.

This is technically defensible from port compatibility, but it feels like the user's search term failed.

### Tool-Using Agent

Path:

1. Add `Manual input`.
2. Search `model` and add an Agent Step variant.
3. Search `browser`.
4. Add `Browser Use`.
5. Open connector bindings.

Observed:

- Browser Use attached to the model as a tool-capability node.
- Node status showed `Capability: tool-capability:ioi.computer_use.native_browser`, `Mode: mock`, and `Credentials: mock`.
- Connector modal showed `Nodes 1`, `Bound 1`, `Mock 1`, `Credentials 0`.
- Connector modal also showed: `tool catalog failed: Cannot read properties of undefined (reading 'invoke'); connector catalog failed: Cannot read properties of undefined (reading 'invoke'); using offline capability presets.`

### Repo Maintenance Attempt

Path:

1. Open node drawer before choosing a starter.
2. Search `repo`.
3. Click the first visible repo-related result.
4. Try to continue composing.

Observed:

- `repo` returned useful items, but the first match was `GitHub Context`, not `Repository Context`.
- Clicking `GitHub Context` opened the node config modal immediately.
- The modal included advanced runtime identity JSON, including `nodeKind`, `actionKind`, `primitiveProjection`, and `runtimeContract`.
- The config modal intercepted subsequent `Add next node` clicks until closed.
- This is useful information for an expert, but it arrives before the user has established an agent topology.

## Frictions

### F1. Runtime Bridge Exceptions Leak Into User-Facing Readiness

Validation and connector catalog fallback both exposed `Cannot read properties of undefined (reading 'invoke')`. The user-facing issue is real, but the message should describe the missing runtime bridge or unavailable saved bundle in product terms.

Impact: users cannot tell whether they should save, bind, restart the desktop shell, open the runtime, or change the graph.

### F2. Capability Binding Repair Is Not Coupled To The Selected Model Node

The node body and selection preview show capability/readiness hints, but the obvious next action is not local to the selected node. The header-level `Bind Models` action opens a global binding modal with rows like `reasoning`, `vision`, `embedding`, and `image`, not a focused repair for the selected Agent Step.

Impact: the right runtime doctrine is present, but the UX makes capability binding feel abstract.

### F3. Compatible Search Can Hide The Thing The User Asked For

After selecting `Manual input`, search defaults to compatible semantics. Searching `repo`, `repository`, `github`, or `branch` returned empty states even though those primitives exist.

Impact: a user trying to build a repo agent after adding an input is told there are no matching primitives, when the real answer is "not directly compatible from this selected port."

### F4. Non-Starter Primitive Adds Interrupt Composition With Full Config

Adding `GitHub Context` opened a config modal before the user could add the agent/model/action/output path. The modal surfaced advanced runtime projection JSON.

Impact: this breaks the "compose topology first, configure details second" mental model.

### F5. Tool Nodes Are Available, But Tool Identity Is Too Plugin-Shaped

Search results label Browser Use as `Tool Pack` but also as `Plugin`, and the binding modal says connector/plugin with capability ids. This is accurate internally, but users likely think in "Browser tool", "Computer tool", "Coding tool", and "Repo tool".

Impact: the primitive taxonomy is improved, but some labels still leak implementation families.

### F6. Status And Bottom Shelf Still Over-Index On Raw Field Counts

Selection preview for Agent Step says `14 configured fields modelRef, modelCapabilityRef, routeId...`. That is good debug information, but weak beginner guidance.

Impact: users see internals instead of a plain lifecycle checklist: input connected, model capability needed, optional tools, output missing, eval missing, ready to run.

### F7. Modal Close Affordances Work, But Escape Did Not Reliably Resume Flow

The model binding modal had visible `Close` and `Done` buttons, and `Close` worked. A scripted `Escape` did not close it during one pass, so the modal intercepted subsequent composition clicks.

Impact: keyboard escape should consistently close non-destructive configuration modals, and modals should make the continuation path explicit.

### F8. Search Result Ranking Can Prefer Adjacent Concepts Over The User's Likely Intent

For `repo`, `GitHub Context` ranked above `Repository Context`. For a generic repo-maintenance agent, the local repository context is probably the safer first result; GitHub and PR nodes are follow-on authority-bound concepts.

Impact: ordinary words should bias toward local, safe, canonical primitives first.

## Proposed Fixes

### P0. Normalize Runtime-Unavailable Errors

Replace raw `invoke` failures with a structured readiness blocker:

- title: `Runtime bridge unavailable`
- body: `The composer could not reach the desktop/runtime bridge needed to read saved workflow bundles or live catalogs.`
- remedies: `Save workflow`, `Retry bridge`, `Open runtime diagnostics`, `Use offline presets`
- technical detail: hidden under `Advanced`.

Regression guard: Playwright should validate that Validate, Run, and connector/model catalog fallback never surface `Cannot read properties of undefined`.

### P0. Add Selected-Node Repair CTAs

For selected Agent Step and Tool Pack nodes, show local repair actions:

- `Bind model capability`
- `Bind tool capability`
- `Add output`
- `Add evaluation`
- `Check readiness`

The global header buttons can remain, but they should deep-link to the selected node row when a selected node has a blocker.

### P0. Make Compatible Search Explain Its Constraint

When a query matches global primitives but zero compatible primitives, show:

`No repo primitives connect directly from Manual input. Show all repo primitives or add an Agent Step first.`

Actions:

- `Show all matches`
- `Add Agent Step`
- `Clear compatibility filter`

Regression guard: with `Manual input` selected, searching `repo` should not render a generic empty state.

### P1. Topology-First Add Mode

Do not auto-open the full config modal for context/state/helper primitives added from search unless the user chose `Configure`. Instead:

- add the node;
- select it;
- show small inline next actions;
- keep advanced config in the inspector/modal.

The exception can be primitives that cannot exist without required config, but those should show a small required-fields panel rather than raw advanced JSON.

### P1. Re-rank Common Intent Queries

Suggested ranking adjustments:

- `repo`: Repository Context, Coding tool pack, Git diff, GitHub Context, Branch Policy, PR Attempt, Review Gate.
- `github`: GitHub Context, Issue Context, PR Attempt, Pull Request, Review Gate.
- `pr` / `pull request`: PR Attempt, Pull Request, Review Gate, Branch Policy.
- `browser`: Browser Use, Browser/computer tool, Computer Use.
- `computer`: Computer Use, Browser/computer tool, Sandboxed Computer, Browser Use.
- `output`: Inline output, File output, Delivery draft, Deploy target, Media output before broad model/function output matches.

### P1. Beginner Inspector Summary Before Raw Fields

Replace the default field-count summary with a lifecycle-aware summary:

- `Input connected`
- `Model capability: local-first route`
- `Tools: none`
- `Output: missing`
- `Receipts: required`
- `Tests: none`
- `Ready: blocked by output`

Move raw field names and primitive projection JSON to `Advanced`.

### P1. Clean Tool Family Labels

Keep `plugin_tool` and connector/plugin capability ids in advanced receipt surfaces, but label default palette results as:

- `Browser tool`
- `Computer tool`
- `Coding tool pack`
- `MCP tool`
- `Workflow tool`

### P2. Optional Guided Composition Mode

After adding a node, keep a small non-blocking "Next" rail visible:

- after input: `Add Agent Step`, `Add Tool`, `Add Output`;
- after Agent Step: `Bind model`, `Attach tool`, `Add output`;
- after Tool Pack: `Bind capability`, `Connect to Agent Step`, `Add verifier`;
- after Output: `Validate`, `Add eval`, `Run`.

This should not replace the full palette; it should reduce modal/drawer churn for common authoring flows.

## Follow-Up Validation Ideas

- Prompt agent: Manual input -> Agent Step -> Inline output -> Validate -> Run. Assert no raw JS errors are surfaced.
- Tool agent: Manual input -> Agent Step -> Browser Use -> Inline output. Assert Browser Use attaches to the model and connector readiness shows user-facing fallback copy.
- Repo agent: search `repo` before and after selecting Manual input. Assert global matches exist and compatible-empty state offers `Show all matches` or `Add Agent Step`.
- Binding repair: select Agent Step and click `Bind model capability`. Assert the modal focuses the selected node or selected model role.
- Config interruption: add Repository/GitHub context from blank drawer. Assert it does not dump the user into advanced JSON by default.
- Ranking: snapshot top five results for `repo`, `git`, `github`, `pr`, `browser`, `computer`, `model`, and `output`.
- Keyboard modal behavior: open model/connector/node config modals and assert `Escape` closes non-destructive modals.
