# Autopilot Chat And VS Code Substrate Deep Integration Master Guide

Owner: Autopilot / Chat UX / Workspace substrate / Workflow Composer / Direct OpenVSCode bridge

Status: proposed P0 integration leg

Created: 2026-05-18

## Executive Verdict

Autopilot is close enough visually that the mismatch is now more architectural
than cosmetic. The standalone Autopilot chat shell, the workspace substrate
chat dock, the direct OpenVSCode surface, workflow composition, and web
inspection all expose useful parts of the system, but they still behave like
neighboring surfaces instead of one deeply integrated operator workbench.

The right end state is:

> Autopilot Chat and VS Code Studio share one operator substrate. The mature
> VS Code-style chat, command center, sidebar, context picker, workflow/project
> materialization, web inspector, and runtime evidence controls are reused
> across data-window surfaces without creating a second runtime or shadow UI
> truth.

This is not a request to make Autopilot "look like VS Code" in a superficial
way. It is a request to absorb the best substrate behaviors into Autopilot's
own IOI runtime model so chat, code, workflows, projects, inspection, and
receipts feel like one product.

## Current Diagnosis

The current implementation has several signs of shallow integration:

- `ChatIdeHeader` owns only window controls and a drag surface. It does not
  host the VS Code-style command center, workspace search, navigation, or
  operator routing controls.
- `WorkspaceHost` renders its own VS Code-style command center inside the
  workspace substrate toolbar, so the center bar disappears outside workspace
  mode and duplicates chrome when embedded.
- `WorkspaceHost` contains a `WorkbenchAgentDock` that visually approximates a
  VS Code chat dock, while the primary Autopilot chat uses
  `ChatConversationSurface`. These should converge into a shared chat substrate.
- `ChatLocalActivityBar` now has the right direction, but it is still an
  Autopilot-only rail. The VS Code Studio data-window surfaces should use the
  same rail and surface model after absorbing the stronger VS Code sidebar
  affordances.
- Workflow composition can describe projects, agents, and repo flows, but the
  user does not yet see "compose workflow -> materialize real VS Code Studio
  project" as an obvious, tangible happy path.
- The web inspector and computer-use targeting layer do not reliably see,
  identify, and act on VS Code substrate UI elements. That means the substrate
  is not yet sufficiently addressable as a first-class controlled environment.

## Doctrine

- No second runtime.
- No React Flow shadow truth store.
- Daemon/runtime contracts remain source of truth.
- Agentgres records operational truth.
- Wallet authority authorizes power.
- React Flow and VS Code Studio are authoring/projection surfaces.
- Models propose; runtime settles.
- Policy is not tracing.
- Provider names, connector transports, and plugin mechanics must not become
  workflow semantics.
- Chat, workspace, workflows, inspection, and data-window surfaces consume the
  same runtime events, receipts, artifacts, projects, authority posture,
  capabilities, and manifests.

## UX North Star

Autopilot should feel like a single autonomous-systems studio:

```text
open Autopilot
-> command/search from the persistent header
-> chat with agent using the mature VS Code-style composer
-> attach repo/file/runtime/context from one shared context picker
-> compose workflow
-> materialize or open the real project in VS Code Studio
-> run, inspect, and repair using the same operator rail
-> inspect web/workspace targets through stable substrate selectors
-> commit, package, or promote with receipts
```

The center bar should not be a workspace-only ornament. It should become a
first-class `chat-ide-header` component with command center, navigation, active
scope, and operator controls. Workspace mode can still expose workspace-local
toolbar affordances, but it should not own the global command/search center.

## Completion Dashboard

| Slice | Goal | Status | Done when |
| --- | --- | --- | --- |
| Shared substrate contract | Define one operator substrate model across chat, workspace, workflows, and data-window surfaces. | Done / regression guarded | Shared types describe command center, side rail, chat pane, context picker, inspector targets, and project materialization events. |
| Header command center | Lift VS Code substrate center bar into `ChatIdeHeader`. | Done / regression guarded | Center command/search is persistent across chat, workflows, workspace, runs, policy, and settings; workspace no longer duplicates global center chrome. |
| Shared chat pane | Reuse the mature VS Code-style chat pane shape in Autopilot Chat and data-window surfaces. | In progress / docked chrome guarded | `ChatConversationSurface` and `WorkbenchAgentDock` converge on one component family with mode variants. |
| Activity rail convergence | Make data-window surfaces use the same improved chat activity rail semantics. | Not started | Sidebar supports collapsed/expanded modes, consistent icons, profile, search shortcut, and data-window surface routing. |
| Workflow-to-project materialization | Make workflow composition generate/open real VS Code Studio projects. | Not started | A composed repo/project workflow can create a project package, open it in workspace, and show receipts. |
| Workspace bridge deepening | Turn workspace/direct OpenVSCode into an addressable controlled substrate. | Not started | Runtime/web inspector can target substrate UI elements through stable ids, AX metadata, DOM probes, and receipts. |
| Inspector substrate targeting | Make web inspector effectively target VS Code substrate UX. | Not started | Inspector can identify activity rail items, command center, explorer, editor tabs, chat composer, workflow controls, and direct webview bounds. |
| GUI validation net | Prove the integration with live clickthroughs. | Not started | Playwright/autopilot probes cover header command center, chat pane parity, workflow materialization, and inspector targeting. |

## Target Architecture

### Shared Operator Substrate

Introduce a shared operator substrate layer that can be consumed by:

- standalone Autopilot Chat;
- Autopilot shell data-window surfaces;
- workspace substrate preview;
- direct OpenVSCode hosted webview;
- Workflow Composer;
- web/computer-use inspector;
- future hosted/cloud workbench sessions.

The substrate should define:

- `OperatorCommandCenterModel`;
- `OperatorActivityRailModel`;
- `OperatorChatPaneModel`;
- `OperatorContextPickerModel`;
- `OperatorProjectMaterializationModel`;
- `OperatorInspectionTargetModel`;
- `OperatorSurfaceRoute`;
- `OperatorChromeMode`;
- `OperatorRuntimeEvidenceRefs`.

These are projection contracts. They do not own runtime truth.

### Header Command Center

The VS Code substrate command center currently lives in `WorkspaceHost` as
`workspace-workbench-command-center`. The target is to promote this shape into
`ChatIdeHeader`.

Default header zones:

```text
left:
  back / forward
center:
  command center with current scope, search, and command palette entry
right:
  compact runtime status, operator actions, window controls
```

Rules:

- Persistent across all primary surfaces.
- Workspace-specific toolbar controls remain local, but global search/command
  center lives only once.
- Workspace mode should not show two command centers.
- Header command center routes through canonical shell/navigation actions, not
  ad hoc view-specific callbacks.
- It should support keyboard-first interaction: `Ctrl+K`, `Ctrl+P`, and
  surface-aware commands.
- It should provide search targets for files, commands, workflows, runs,
  capabilities, receipts, and settings.

Implementation notes:

- Extract command center logic and icon treatments from
  `packages/workspace-substrate/src/components/WorkspaceHost.tsx`.
- Add a reusable component, likely under
  `apps/autopilot/src/windows/AutopilotShellWindow/components/` first, then
  promote to a package when stable.
- Teach `WorkspaceHost` to accept `commandCenterSlot` or
  `hideGlobalCommandCenter` so embedding mode can defer to the shell header.
- Do not let direct OpenVSCode own shell-level global commands.

### Shared Chat Pane

Autopilot currently has:

- `ChatConversationSurface` for primary chat;
- `WorkbenchAgentDock` inside the workspace substrate;
- right-side auxiliary chat pane behavior in the shell;
- chat controls in multiple local shapes.

The target is a single shared chat pane component family:

```text
OperatorChatPane
  mode: full | sidebar | docked | floating | embedded
  chrome: standalone | substrate | data-window
  surfaces: chat | workflows | runs | artifacts | policy | connections
  composer: shared model picker + context picker + slash menu
  controls: new, search, settings, expand/collapse, close
```

Default behavior:

- Full chat uses the polished VS Code/Codex-style center composition.
- Sidebar chat uses the responsive compact variant, not the full session list
  layout.
- Workspace chat dock uses the same component, configured as `mode=docked`.
- Data-window surfaces use the same sidebar and pane controls.
- Expand/minimize/close are visually quiet and placed consistently with VS Code
  expectations.

What not to do:

- Do not keep copying screenshots into invisible hitboxes as long-term UI.
- Do not maintain separate command/search/slash-menu variants per pane.
- Do not make session history occupy sidebar mode unless the sidebar has enough
  width and the mode asks for it.

### Activity Rail And Data-Window Surfaces

The collapsible `ChatLocalActivityBar` is close to the desired shape. The next
step is to make it the rail used by VS Code Studio data-window surfaces after
absorbing substrate sidebar behavior.

Target rail:

- collapsed icon rail with no logo, just the collapse/expand affordance;
- expanded rail with Home, Search, Notifications, Recent/Workspace,
  Workflows, Runs, Capabilities, Policy, Settings, and profile;
- only `Ctrl+K` shown by default for Search;
- profile shows the user/profile, not the project name;
- theme tokens inherited from current surface;
- data-window surface ids recorded through `data-window-surface`;
- routes are deterministic shell actions, not local UI switches.

### Workflow Composition To Real Projects

The Workflow Composer should stop feeling like a graph-only surface. Composing
an autonomous system should be able to produce a tangible VS Code Studio
project.

Target happy path:

```text
Create workflow from prompt
-> choose project/repo package template
-> bind model and tool capabilities
-> generate project files/workflow manifest/evals
-> open in VS Code Studio substrate
-> run fixture or dry run
-> inspect receipts in chat/workspace
```

Required contracts:

- `WorkflowProjectMaterializationRequest`;
- `WorkflowProjectMaterializationReceipt`;
- `GeneratedProjectDescriptor`;
- `WorkspaceOpenReceipt`;
- `AutonomousSystemPackageRef`;
- `ProjectArtifactRefs`;
- `EvaluationFixtureRefs`.

Rules:

- Workflow graph remains a deterministic manifest/projection.
- Project materialization writes through proposal-first filesystem/Git
  capabilities where mutation is involved.
- Generated projects open through the existing workspace bridge and inherit the
  shared operator substrate.
- The user sees the generated files and receipts in VS Code Studio, not just a
  graph success state.

### Web Inspector And Substrate Targeting

The current direct OpenVSCode webview bridge exposes bounds and devtools hooks,
but the inspector needs a richer target model for VS Code substrate UX.

Target:

- direct webview bounds are always available as an inspectable target;
- substrate UI elements expose stable ids/labels where we control them;
- direct OpenVSCode targets expose a bridge-side target index where possible;
- computer-use actions resolve through DOM/AX/selector/coordinate target
  indexes before falling back to raw coordinates;
- inspector overlays can name:
  - activity rail item;
  - command center;
  - explorer row;
  - editor tab;
  - editor symbol;
  - terminal panel;
  - chat composer;
  - workflow node;
  - workflow palette item;
  - run/evidence row.

Contracts:

- `WorkspaceSubstrateTargetIndex`;
- `WorkspaceSubstrateObservationBundle`;
- `WorkspaceSubstrateActionReceipt`;
- `DirectWebviewInspectionTarget`;
- `SubstrateElementLocator`;

This should integrate with the broader computer-use/browser-use target state,
not create a special inspector runtime.

## Implementation Plan

### Slice 1: Inventory And Contract Spine

Goal: define shared substrate contracts and remove ambiguity.

Tasks:

- Inventory chat, workspace, workflow, activity rail, direct webview, and
  inspector component boundaries.
- Add shared TypeScript model definitions for operator substrate projections.
- Document which fields are runtime truth vs UI projection.
- Add static tests that prevent duplicate command center ownership in embedded
  workspace mode.

Acceptance:

- A guide and type contracts explain where header, rail, chat pane, context
  picker, and inspector target state live.
- No second runtime or React Flow truth store is introduced.

### Slice 2: Persistent Header Command Center

Goal: move the center bar into `ChatIdeHeader`.

Tasks:

- Build `OperatorCommandCenter` from the VS Code substrate center bar shape.
- Wire it into `ChatIdeHeader`.
- Add commands for Chat, Workspace, Workflows, Runs, Capabilities, Policy,
  Settings, Open File, Search Workspace, Open Recent, and New Workflow.
- Teach `WorkspaceHost` embedded mode to hide its global command center or
  render only workspace-local controls.
- Preserve Tauri drag and window controls.

Acceptance:

- Header command center is visible in chat, workspace, workflows, and policy.
- Workspace mode has one global center bar, not two.
- `Ctrl+K` opens the same command surface from every primary view.

### Slice 3: Shared Chat Pane Component

Goal: converge Autopilot chat and workspace dock chat.

Tasks:

- Extract shared chat pane chrome from `ChatConversationSurface`.
- Replace `WorkbenchAgentDock` screenshot/hitbox UI with the shared component
  in docked mode.
- Keep full, sidebar, and docked variants responsive.
- Unify chat controls: new, search, settings, expand/collapse, close.
- Keep session history visible only in modes where it is useful.

Acceptance:

- Primary chat and workspace dock share the same component family.
- Sidebar chat does not inherit fullscreen session layout.
- Pane controls match one consistent VS Code-like row.

### Slice 4: Activity Rail As Shared Data-Window Surface Rail

Goal: make the rail the common surface switcher.

Tasks:

- Promote `ChatLocalActivityBar` semantics into a shared rail component.
- Wire data-window surface ids to all rail entries.
- Add collapsed/expanded parity probes.
- Ensure theme tokens work in light and dark mode.
- Remove duplicated per-surface rail variants where possible.

Acceptance:

- Same rail component works in standalone chat and VS Code Studio substrate
  surfaces.
- Only Search shows `Ctrl+K` in expanded mode.
- Profile/avatar represents the user profile.

### Slice 5: Workflow-To-Project Materialization

Goal: make composed workflows produce real VS Code Studio projects.

Tasks:

- Define materialization request/receipt contracts.
- Add a Workflow Composer action: `Create project from workflow`.
- Generate a minimal project structure for prompt agents, tool agents, and repo
  agents.
- Open generated project in workspace substrate.
- Record project artifacts, manifest refs, eval refs, and receipts.

Acceptance:

- A user can compose a workflow, materialize it, and immediately inspect files
  in VS Code Studio.
- Filesystem/Git mutation remains proposal-first where relevant.

### Slice 6: Inspector Targeting For Substrate UX

Goal: make the web inspector understand VS Code substrate UI.

Tasks:

- Add data attributes and accessible labels to controlled substrate chrome.
- Export target index snapshots from Autopilot shell and workspace substrate.
- Bridge direct OpenVSCode target metadata where possible.
- Add inspector probes that target command center, rail, explorer, editor,
  chat composer, workflow node, and run/evidence rows.

Acceptance:

- Inspector can identify and act on substrate elements without brittle raw
  coordinates for controlled Autopilot UI.
- Direct OpenVSCode fallback remains bounded, visible, and receipted.

### Slice 7: Validation And Regression Net

Goal: prove the deep integration with live GUI behavior.

Required probes:

- Header command center visible and usable in all primary surfaces.
- Workspace has no duplicate center command bar.
- Chat full/sidebar/docked modes share controls and theme.
- Workflow composition materializes a project and opens it in workspace.
- Generated project has manifest, workflow, eval fixture, and receipts.
- Inspector selects activity rail, command center, explorer row, editor tab,
  chat composer, and workflow node.
- Existing workflows and repository opening still work.
- Dark/light themes remain consistent.

## Component Map

| Current area | Current file(s) | Target role |
| --- | --- | --- |
| Shell header | `apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx` | Own global command center, nav, scope, runtime status, and window controls. |
| Workspace command center | `packages/workspace-substrate/src/components/WorkspaceHost.tsx` | Provide extracted command-center implementation and optional local toolbar controls. |
| Primary chat shell | `apps/autopilot/src/windows/ChatShellWindow/components/ChatConversationSurface.tsx` | Source for shared chat pane chrome and controls. |
| Workspace agent dock | `packages/workspace-substrate/src/components/WorkspaceHost.tsx` / `WorkbenchAgentDock` | Replace with shared `OperatorChatPane` docked mode. |
| Activity rail | `apps/autopilot/src/windows/AutopilotShellWindow/components/ChatLocalActivityBar.tsx` | Promote into shared activity/data-window surface rail. |
| Direct OpenVSCode webview | `apps/autopilot/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx` | Provide bounded target metadata and inspection hooks. |
| Workspace bridge | `apps/autopilot/src/services/workspaceIde.ts` and `workspaceDirectWebview.ts` | Carry project materialization/opening and target-index receipts. |
| Workflow Composer | `packages/agent-ide/src/WorkflowComposer` and `packages/agent-ide/src/runtime` | Materialize projects from deterministic manifests. |

## Product Shape Rules

- The header is global. Surface headers are local.
- The command center is global. Workspace search can be a command result or
  local explorer mode, not a duplicate top-level bar.
- Chat pane chrome is shared. Content can vary by mode.
- The rail is shared. Surface routing can vary by host.
- The canvas is for topology. Project materialization and receipts belong in
  workspace/chat/evidence surfaces.
- Inspector targeting is a runtime/computer-use affordance, not a test-only
  convenience.
- Advanced details remain available, but default surfaces should use ordinary
  authoring language.

## Risks If Ignored

- Autopilot will keep looking polished in isolated screens but fragmented in
  real operator flows.
- Workflow composition will feel abstract rather than producing tangible
  autonomous-system projects.
- Browser/computer-use will keep needing brittle coordinate fallback against
  Autopilot's own UI.
- VS Code Studio will remain a hosted surface beside Autopilot rather than a
  deeply integrated substrate.
- Phase 5 connectors will add more surface area before the core operator model
  is unified.

## Open Questions

- Should the shared operator substrate live first in `apps/autopilot` or be
  promoted immediately into `packages/workspace-substrate`?
- Should direct OpenVSCode target indexing come from injected extension code,
  a bridge polling file, CDP/DOM inspection, or a hybrid?
- Should workflow materialization generate a complete project from day one or
  start with a minimal package scaffold plus manifest/eval fixtures?
- Which VS Code command-center shortcuts should be exact parity versus
  Autopilot-native?
- Should the workspace substrate eventually wrap OpenVSCode chrome directly or
  remain a peer overlay around the direct webview?

## Phase Decision

This should be treated as a P0/P1 leg before broad new connector UX. The product
can continue small bug fixes, but major Phase 5 connector expansion should not
outrun this substrate integration because every connector will otherwise need
to choose between chat, workspace, workflow, and inspector-specific UI paths.

Recommended decision:

> Split the next work into a Deep Operator Substrate pass first, then resume
> broad connector expansion once chat, workspace, workflow materialization, and
> inspector targeting share the same shell-level model.
