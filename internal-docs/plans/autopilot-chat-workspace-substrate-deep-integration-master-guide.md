# Autopilot Chat And VS Code Substrate Deep Integration Master Guide

Owner: Autopilot / Chat UX / Workspace substrate / Workflow Composer / Direct OpenVSCode bridge

Status: complete / native chat chrome parity traced and regression guarded

Created: 2026-05-18

Follow-on native endpoint:
`internal-docs/plans/openvscode-native-autopilot-contribution-replacement-master-guide.md`
tracks the next architectural target: replacing native OpenVSCode chat and
command contribution ownership at fork/contribution level rather than relying
on shell-side rendering plus OpenVSCode chrome suppression.

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
| Shared chat pane | Reuse the mature VS Code-style chat pane shape in Autopilot Chat and data-window surfaces. | Done / visual parity guarded | Primary chat, sidebar chat, workspace dock chat, and data-window chat use the same shared `OperatorChatPane` component family, empty state, composer chrome, control order, theme tokens, spacing scale, and responsive modes. |
| Activity rail convergence | Make data-window surfaces use the same improved chat activity rail semantics. | Done / regression guarded | Sidebar supports collapsed/expanded modes, consistent icons, profile, search shortcut, and data-window surface routing. |
| Workflow-to-project materialization | Make workflow composition generate/open real VS Code Studio projects. | Done / regression guarded | A composed workflow emits an Autonomous System Package scaffold, persists it as a workspace repository, hands it off for workspace opening, and fail-closes with user-facing copy outside desktop runtime. |
| Workspace bridge deepening | Turn workspace/direct OpenVSCode into an addressable controlled substrate. | Done / target-index guarded | Controlled workspace substrate chrome exposes stable inspection targets; direct OpenVSCode exposes bounded surface metadata and target-index snapshots for fallback. |
| Inspector substrate targeting | Make web inspector effectively target VS Code substrate UX. | Done / controlled-target guarded | Inspector targets cover activity rail, command center, workspace rail/explorer/editor/terminal/chat chrome, workflow composer/canvas/nodes/palette, run evidence, and direct webview bounds. |
| GUI validation net | Prove the integration with live clickthroughs. | Done / visual parity guarded | Playwright/autopilot probes cover command center, no duplicate workspace center bar, command palette, workflow materialization, substrate inspection markers, and screenshot/layout parity for full, sidebar, docked, and data-window chat panes. |

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

## Validation Snapshot

Closeout on 2026-05-18:

- Added `OperatorChatPane` in `packages/workspace-substrate` and routed full
  chat, compact/sidebar chat, and workspace dock chat through that shared pane
  family with mode-specific layout, shared header/action ordering, inspection
  targets, and shared theme tokens.
- Replaced the workspace dock's separate `WorkbenchAgentDock` chrome with
  `OperatorChatPane mode=docked`; static guards now reject screenshot/hitbox
  chat dock artifacts and separate dock chrome.
- Added `operator-chat-composer` and `workspace-chat-composer` inspection
  targets so computer-use/web-inspector probes can target the composer through
  semantic DOM before coordinate fallback.
- Normalized runtime-unavailable copy across Workflow Composer, Fleet/Runs,
  Workspace open, and Capabilities registry failures so default UI no longer
  surfaces raw `Cannot read properties of undefined (reading 'invoke')`
  messages; original details stay behind Advanced detail where applicable.
- Live Playwright/autopilot probes against `http://127.0.0.1:1428` verified
  full chat, sidebar chat on Runs, workspace-open fail-closed posture,
  Workflows loading, command-center activation, Capabilities fail-closed copy,
  and dark/light chat pane rendering. Screenshots were written outside git to
  `/tmp/autopilot-chat-parity`.

Correction on 2026-05-18:

- The previous completion state overstated the shared chat-pane result. The
  implementation unified targetability and control semantics, but screenshots
  still show materially different chat panes between Autopilot Chat and the VS
  Code Studio substrate.
- The master guide north star was correct, but the completion dashboard accepted
  "chrome contract" parity where true user-facing parity required a shared
  component family and visual/layout regression checks.
- The leg is reopened until the shared chat pane is implemented as product UI,
  not just as compatible inspection/control contracts.

Follow-up correction on 2026-05-18:

- User validation caught two remaining nonconformities after the parity pass:
  embedded/direct OpenVSCode could still surface its own quick-open/command
  palette affordance, and the persistent Autopilot chat sidebar still carried
  a legacy wrapper around the shared pane.
- The fix makes `ChatIdeHeader` the only global command/search owner: OpenVSCode
  user settings disable command center and layout-control chrome, generated
  keybindings unbind quick-open/show-command chords, stale direct sessions are
  relaunched if those files are missing, Home onboarding now routes quick-open
  intent to the Autopilot command center, and the bundled OpenVSCode extension
  no longer advertises a separate command-palette action.
- The persistent chat sidebar now renders the shared `OperatorChatPane` shell
  directly, chat pane actions use the same VS Code-style ordering, and `More`
  replaces pane-local Search so command discovery consistently flows through
  the global command center.

Completed validation:

- Added `scripts/lib/openvscode-chat-parity-audit.mjs`, which can temporarily
  reveal the hidden legacy OpenVSCode auxiliary chat pane, capture a screenshot,
  extract its DOM/action geometry, and trace safe menu/toggle interactions into
  `/tmp/autopilot-chat-parity`. The captured native reference confirms:
  `codicon-plus`, `codicon-chevron-down`, `codicon-gear`,
  `codicon-toolbar-more`, separator, `codicon-auxiliarybar-maximize`, and
  `codicon-auxiliarybar-close` with 22px/16px action boxes.
- Updated the shared `OperatorChatPane` and Autopilot chat projection to carry
  those native labels, codicon classes, action sizes, divider placement, and
  expand/close semantics while keeping one Autopilot-owned chat substrate.
- Tightened the functional composer toward the prior VS Code substrate shape:
  compact target/capability codicon selectors, `Auto`, tools, and native
  `codicon-send`, with settings remaining in the chat title bar.
- `npx tsx --test packages/agent-ide/src/runtime/workflow-runtime-unavailable-copy.test.ts apps/autopilot/src/services/workspaceRepositoryRegistry.test.ts`
- `node --test apps/autopilot/src/windows/AutopilotShellWindow/operatorSubstrateModel.test.ts apps/autopilot/src/windows/AutopilotShellWindow/workflowComposerWiring.test.ts apps/autopilot/src/windows/ChatShellWindow/index.seedIntent.test.ts apps/autopilot/src/windows/AutopilotShellWindow/components/AutopilotShellContent.seedIntent.test.ts`
- `node --test apps/autopilot/src/windows/AutopilotShellWindow/operatorSubstrateModel.test.ts apps/autopilot/src/services/workflowProjectMaterializationPlan.test.ts apps/autopilot/src/services/workspaceRepositoryRegistry.test.ts`
- `npm run build --workspace=apps/autopilot`
- `cargo test openvscode_user_config --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `cargo check --manifest-path apps/autopilot/src-tauri/Cargo.toml`
- `git diff --check`
- Live Playwright probe against `http://127.0.0.1:1428`:
  - verified exactly one `[data-operator-chat-pane]` in full and sidebar chat
    modes, with shared header/actions, targetable composer, and no legacy
    `.spot-workbench-chat-topbar`, `.workspace-agent-dock-header`, or
    `.workspace-agent-dock` chrome;
  - verified workspace repository open fails closed with user-facing runtime
    bridge copy and Advanced detail instead of raw bridge exceptions;
  - verified Capabilities registry failures use the same user-facing runtime
    bridge copy instead of raw bridge exceptions;
  - captured dark and light mode screenshots for the shared pane;
  - verified exactly one `[data-operator-command-center]` on Home, Chat,
    Workspace, Workflows, Runs, Capabilities, Policy, and Settings;
  - verified Workspace does not render a duplicate
    `.workspace-workbench-command-center` in embedded mode;
  - verified full Chat renders one shared `[data-operator-chat-pane]`, no
    `.chat-chat-pane-body` legacy wrapper, a `More` pane action, and no
    pane-local Search action;
  - verified embedded Workspace renders one Autopilot command center, no
    duplicate OpenVSCode command-center chrome, and no quick-open input in the
    default workspace shell;
  - verified command-center click and `Ctrl+K` open the global command
    palette;
  - verified Workflow Composer, canvas, command center, and activity rail
    expose inspection targets;
  - verified `Create project` fail-closes with user-facing desktop-runtime copy
    in browser mode and does not surface raw Tauri/JS exceptions;
  - verified no page errors during the primary-surface substrate probe.

Known boundary:

- Controlled Autopilot and workspace-substrate chrome is DOM/selector
  targetable. Direct OpenVSCode internals remain bounded by direct webview
  surface metadata until an injected extension/CDP bridge is added; this is an
  explicit substrate boundary, not a second runtime.

## Component Map

| Current area | Current file(s) | Target role |
| --- | --- | --- |
| Shell header | `apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx` | Own global command center, nav, scope, runtime status, and window controls. |
| Workspace command center | `packages/workspace-substrate/src/components/WorkspaceHost.tsx` | Provide extracted command-center implementation and optional local toolbar controls. |
| Shared chat pane | `packages/workspace-substrate/src/components/OperatorChatPane.tsx` | Canonical full/sidebar/docked/embedded/floating chat pane chrome, action row, empty state, composer slot, theme tokens, and inspection targets. |
| Primary chat shell | `apps/autopilot/src/windows/ChatShellWindow/components/ChatConversationSurface.tsx` | Projects primary/full and compact/sidebar chat into `OperatorChatPane` while preserving session, context, model, and slash-command behavior. |
| Workspace chat dock | `packages/workspace-substrate/src/components/WorkspaceHost.tsx` | Renders docked operator chat through `OperatorChatPane mode=docked`; no separate `WorkbenchAgentDock` chrome remains. |
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
