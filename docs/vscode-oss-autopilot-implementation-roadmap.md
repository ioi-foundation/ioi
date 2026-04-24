# VS Code OSS × Autopilot Implementation Roadmap

Companion to the audit: [VS Code OSS × Autopilot Componentization Audit](/home/heathledger/Documents/ioi/repos/ioi/docs/vscode-oss-autopilot-componentization-audit.md)

## 1. Purpose

This roadmap turns the audit into an execution program. The goal is not to make Autopilot “more like VS Code” in the abstract. The goal is to make the product feel like one coherent system where:

- OpenVSCode owns the local code-workbench muscle inside Workspace.
- IOI owns runtime authority, evidence, policy, approvals, workflows, and tool/skill execution.
- Chat stops feeling like the weaker cousin of Workspace and instead becomes a codebase-aware, workbench-grade shell over the same runtime.

## 2. Program Objective

Build a product state where:

1. Workspace remains the real contained OpenVSCode workbench.
2. Chat adopts the workbench’s visual seriousness, interaction density, and codebase-first posture.
3. Workbench actions and Chat actions route into one runtime/session substrate.
4. IOI panes inside Workspace become runtime-backed product surfaces instead of shallow bridge-fed projections.
5. Review, validation, evidence, and artifact inspection use Code-OSS-grade interaction patterns without surrendering canonical authority to IDE UI state.

## 3. Invariants

These are non-negotiable throughout the roadmap:

1. **Runtime authority stays ours.**
   - Execution, approvals, evidence, validation, workflows, and settlement remain in `crates/services`, `crates/validator`, `crates/types`, and `crates/api::runtime_harness`.

2. **OpenVSCode remains a workbench substrate, not the product shell.**
   - Workspace is code-first.
   - Chat remains a distinct shell.

3. **The extension host never becomes the execution authority.**
   - Workbench commands may invoke our runtime.
   - They do not become a second agent runtime.

4. **Chat should learn from the workbench, not impersonate it.**
   - We should adopt typography, spacing, command grammar, and contextuality.
   - We should not clone full workbench chrome into Chat.

5. **Canonical proof artifacts stay ours.**
   - Problems panels, logs, or workbench state are not settlement proof.

## 4. Definition of Done

This roadmap is complete when all of the following are true:

1. The default Workspace experience remains the contained direct OpenVSCode host.
2. Chat uses a workbench-grade visual system and no longer reads as a softer, lower-density sibling to Workspace.
3. Chat can start and continue sessions with explicit workspace/file/selection context in a codebase-first way.
4. Workspace-native IOI panes are backed by live runtime state for chat, workflows, runs, artifacts, policy, and connections.
5. Editor/explorer/context actions in Workspace route into our runtime cleanly and predictably.
6. Evidence, diff, validation, and artifact review use stronger Code-OSS-style inspection patterns while preserving IOI authority semantics.
7. Retained proof exists for key behaviors, not just screenshots and not just local optimism.

## 5. Workstreams

### WS1. Visual System Convergence

**Goal**

Make the broader Autopilot shell feel like it belongs next to the OpenVSCode workbench instead of reading as a different product family.

**Primary modules**

- [ChatWindow.css](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/ChatWindow.css)
- [ChatIdeHeader.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/components/ChatIdeHeader.tsx)
- [ChatLocalActivityBar.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/components/ChatLocalActivityBar.tsx)
- [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx)
- `apps/autopilot/src/components/CommandPalette.css`
- [ChatShellWindow/index.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/index.tsx)
- `apps/autopilot/src/windows/ChatShellWindow/styles/*`

**Deliverables**

1. Adopt a workbench-aligned font stack and type scale where licensing/distribution permits.
2. Normalize control density, icon sizing, panel rhythm, hover/focus treatment, and empty-state styling across Chat and the surrounding shell.
3. Rework the Chat header, activity bar, palette, and conversation shell so they visually harmonize with Workspace.
4. Remove decorative or overly editorial styling that weakens developer-tool legibility.

**Acceptance criteria**

1. The Workspace shell and Chat shell can be shown side by side without obvious typography, density, or chrome mismatch.
2. The command palette reads more like a power-user workbench surface than a product modal.
3. Chat no longer depends on oversized welcome-card composition or low-density chrome for primary navigation.

**Anti-goals**

- Do not make Chat a clone of the VS Code workbench.
- Do not bury product-specific surfaces like workflows, policy, or capabilities under generic IDE chrome.

### WS2. Codebase-First Chat Context

**Goal**

Make Chat feel as grounded in the current repo, files, and selections as Workspace already does.

**Primary modules**

- [ChatShellWindow/index.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/index.tsx)
- [useChatFileContext.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/hooks/useChatFileContext.ts)
- [sessionFileContext.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/sessionFileContext.ts)
- [workspaceAdapter.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceAdapter.ts)
- [workspaceRuntimeNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceRuntimeNavigation.ts)
- [runtimeChatNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/runtimeChatNavigation.ts)
- [useChatWindowController.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/useChatWindowController.ts)

**Deliverables**

1. Expose current workspace root, pinned files, recent files, explicit includes, and explicit excludes in the Chat shell as first-class context.
2. Make composer bootstrapping context-aware so repo/file/selection state naturally shapes the initial ask.
3. Build a lightweight codebase orientation surface in Chat:
   - current repo
   - current branch or file posture where available
   - selected file(s)
   - recent/pinned context
4. Ensure Chat follow-up flows can continue with the same retained codebase context instead of feeling detached from the repo.

**Acceptance criteria**

1. A user can enter Chat from Workspace and immediately see what codebase context is active.
2. File-aware and selection-aware prompts retain enough context that the user does not need to restate the repo/file relationship manually.
3. Session file context mutation APIs are visible and useful in the Chat experience, not just present in backend plumbing.

**Anti-goals**

- Do not move full explorer/search/source-control UI into Chat.
- Do not create a separate Chat-only file-context model that diverges from the workspace/session substrate.

### WS3. Workbench-Native IOI Panes

**Goal**

Turn the IOI workbench container into a set of genuinely useful runtime-backed panes.

**Primary modules**

- [package.json](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/package.json)
- [extension.js](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/extension.js)
- [workspaceBridgeState.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceBridgeState.ts)
- [openVsCodeWorkbenchSession.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/openVsCodeWorkbenchSession.ts)
- [workspaceRuntimeNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceRuntimeNavigation.ts)
- [workspace_workflows.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workspace_workflows.rs)

**Deliverables**

1. Make `ioi.chat`, `ioi.workflows`, `ioi.runs`, `ioi.artifacts`, `ioi.policy`, and `ioi.connections` reflect live runtime state.
2. Replace purely presentational or generic webview patterns with workbench-native interaction where possible.
3. Improve bridge-state richness so workbench panes can show meaningful summaries, recency, linked sessions, and next actions.
4. Ensure every pane routes deeper actions back into Chat/runtime targets instead of trapping users inside a dead-end webview.

**Acceptance criteria**

1. Opening IOI panes in Workspace reveals live project/runtime state, not static scaffolding.
2. Workbench commands such as file review, selection review, run review, and evidence review produce reliable runtime navigation.
3. A developer can stay inside Workspace to inspect runs, workflows, artifacts, policy posture, and connections without the panes feeling fake.

**Anti-goals**

- Do not treat webview content as a long-term excuse for weak pane design.
- Do not push agent execution semantics down into the extension host.

### WS4. Command, Palette, and Contextual Entry-Point Convergence

**Goal**

Unify how Chat and Workspace discover and invoke actions, while keeping our richer runtime graph intact.

**Primary modules**

- [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx)
- `apps/autopilot/src/components/CommandPalette.css`
- [package.json](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/package.json)
- [extension.js](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/extension.js)
- [chatShellNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/chatShellNavigation.ts)
- [runtimeChatNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/runtimeChatNavigation.ts)
- [session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts)

**Deliverables**

1. Redesign the command palette interaction grammar around faster search, clearer ranking, stronger keyboard handling, and more workbench-like affordances.
2. Align Chat-side and Workspace-side command names and action semantics.
3. Make editor-context commands, explorer-context commands, and palette actions map to the same runtime intent builders.
4. Prepare a clear path for inline chat or contextual ask flows that still land on our session runtime.

**Acceptance criteria**

1. The same user intent can be launched from Chat, command palette, or Workspace context menus without semantic drift.
2. The palette feels coherent even with sessions, skills, live tools, workflows, projects, and capabilities mixed together.
3. Command routing is explainable and debuggable from runtime logs and bridge requests.

**Anti-goals**

- Do not flatten skills/tools/workflows into generic commands with lost metadata.
- Do not create multiple intent builders for the same action family.

### WS5. Evidence, Review, and Inspection Convergence

**Goal**

Upgrade our evidence and review UX until it matches the quality of our runtime semantics.

**Primary modules**

- [ArtifactSourceWorkbench.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ArtifactSourceWorkbench.tsx)
- [ArtifactEvidencePanel.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ArtifactEvidencePanel.tsx)
- [WorkspaceEditorPane.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx)
- [workspaceAdapter.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceAdapter.ts)
- [validation_preview.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/validation_preview.rs)
- [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs)

**Deliverables**

1. Recast artifact, diff, validation, and receipt inspection using stronger Code-OSS review patterns:
   - better side-by-side or inline diff posture
   - more legible issue grouping
   - clearer navigation between evidence, produced files, and validation
2. Make artifact inspection feel like a serious review surface rather than a long custom dossier.
3. Ensure evidence-linked drilldowns preserve canonical IOI semantics.
4. Use the shared editor substrate wherever code inspection belongs in an editor, not in a custom card stack.

**Acceptance criteria**

1. Reviewing an artifact, generated file, diff, or validation finding feels closer to workbench review than to a dashboard panel.
2. Receipts, validation outcomes, and evidence remain semantically distinguished even when shown in more IDE-like surfaces.
3. Users can move from an artifact summary into source, evidence, validation, and receipt detail without losing orientation.

**Anti-goals**

- Do not replace evidence with generic logs or diagnostics.
- Do not rebuild workbench chrome in React if the shared editor substrate already solves the problem.

### WS6. Shared Runtime and Bridge Hardening

**Goal**

Keep one runtime story across Chat and Workspace, and make the bridge explicit, observable, and boringly reliable.

**Primary modules**

- [directWorkspaceWorkbenchHost.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/directWorkspaceWorkbenchHost.ts)
- [openVsCodeWorkbenchSession.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/openVsCodeWorkbenchSession.ts)
- [OpenVsCodeDirectSurface.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/OpenVsCodeDirectSurface.tsx)
- [workspaceBridgeState.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceBridgeState.ts)
- [TauriRuntime.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/TauriRuntime.ts)
- [session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts)

**Deliverables**

1. Make runtime-to-workbench bridge state rich enough for real panes and contextual actions.
2. Ensure Chat and Workspace use the same runtime targets and session semantics wherever they overlap.
3. Improve diagnostics for bridge requests, bridge state publication, and navigation outcomes.
4. Keep iframe oracle support only as a diagnostic comparison path, never as product fallback.

**Acceptance criteria**

1. The same action launched from Workspace or Chat lands on the same session/runtime truth.
2. Bridge failures are visible and diagnosable instead of silently degrading into empty panes.
3. There is no production dependence on legacy substrate-preview behavior for real workbench UX.

**Anti-goals**

- Do not build a parallel runtime adapter stack for Workspace-only actions.
- Do not regress the contained direct workbench host.

## 6. Sequencing

### Phase 0. Baseline and Guardrails

**Purpose**

Create the rails that keep later work honest.

**Ship**

1. Roadmap acceptance checklist and retained-proof expectations.
2. A lightweight visual-system inventory of current Chat vs Workspace tokens.
3. A context-flow map for:
   - workspace root
   - file context
   - selection context
   - command routing
   - review/evidence navigation

**Exit condition**

We can point to the exact modules and proof surfaces for each later phase.

### Phase 1. Chat Visual Convergence + Codebase Context

**Purpose**

Close the most obvious product gap first: Chat feels visually weaker and less grounded than Workspace.

**Ship**

1. WS1 first pass:
   - typography
   - density
   - header/activity bar cleanup
   - command palette restyling
2. WS2 first pass:
   - visible repo/file context in Chat
   - pinned/recent/included file context surfaces
   - smoother workspace-to-chat handoff

**Exit condition**

A user entering Chat from Workspace can tell what repo they are in, what context is active, and does not feel like they moved into a visually softer app.

### Phase 2. Workbench Panes + Command Routing

**Purpose**

Turn the workbench-side IOI experience into something people can actually use daily.

**Ship**

1. WS3 first pass:
   - runtime-backed `ioi.*` panes
   - richer bridge state
2. WS4 first pass:
   - aligned command naming
   - stronger palette grammar
   - reliable editor/explorer/context action routing

**Exit condition**

Workspace users can browse IOI state and launch meaningful runtime actions without feeling shunted into placeholders.

### Phase 3. Evidence and Review Upgrade

**Purpose**

Bring our strongest semantics up to the review quality they deserve.

**Ship**

1. WS5 first pass:
   - stronger diff/review posture
   - editor-backed artifact/file inspection
   - cleaner navigation between evidence, files, validation, and receipts
2. WS4 follow-through:
   - inline/contextual ask flows that still use our runtime

**Exit condition**

Artifact and validation review is no longer obviously worse than Code OSS review ergonomics.

### Phase 4. Runtime Consolidation and Cleanup

**Purpose**

Make the resulting architecture simpler and harder to regress.

**Ship**

1. WS6 hardening:
   - bridge diagnostics
   - session/runtime convergence cleanup
   - dead-path quarantine
2. Remove or quarantine stale shell/facade code that no longer represents the product direction.

**Exit condition**

We have one clear runtime story, one clear workbench story, and fewer legacy seams pretending to be strategic.

## 7. Dependencies

The critical dependency order is:

1. **WS6 before deep WS3**
   - richer, more reliable bridge state makes better panes possible.

2. **WS1 before broad WS4**
   - the command system should land in a shell that already feels closer to workbench quality.

3. **WS2 before inline/contextual chat expansion**
   - codebase-first context has to be trustworthy before we multiply entry points.

4. **WS5 after WS2 and WS4 first passes**
   - review surfaces are only as good as their context model and action routing.

## 8. Proof and Validation

No phase should be declared done without retained evidence.

### Required proof types

1. **Whole-surface screenshots**
   - Chat
   - Workspace
   - cross-surface transitions

2. **Retained interaction probes**
   - Workspace context actions
   - workbench-pane navigation
   - runtime routing from editor/explorer commands

3. **State evidence**
   - bridge state payload samples
   - request-routing logs
   - representative runtime targets reached from workbench commands

4. **Behavior proof**
   - manual browse sessions where a developer can move through repo, files, selection review, run review, and evidence review without falling into dead ends

### Minimum acceptance per major lane

**WS1**
- before/after screenshots for Chat primary surfaces
- explicit inventory of adopted vs remaining divergent visual tokens

**WS2**
- proof that pinned/recent/included file context changes what Chat sees
- proof that workspace-to-chat handoff carries repo/file/selection context

**WS3**
- proof that each IOI workbench pane shows live runtime-backed data
- proof that pane actions route into runtime targets

**WS4**
- proof that equivalent actions launched from palette, editor, explorer, or pane land on the same runtime semantics

**WS5**
- proof that artifact/file review uses stronger editor/review affordances
- proof that evidence semantics remain canonical

**WS6**
- proof that direct OpenVSCode hosting remains the default production path
- proof that iframe remains oracle-only

## 9. Non-Targets

This roadmap deliberately does **not** aim to:

1. Turn Chat into a full IDE shell.
2. Let the VS Code extension host become the agent runtime.
3. Treat skills as if they were plain extensions.
4. Replace evidence/approval semantics with workbench logs, badges, or diagnostics.
5. Rebuild the OpenVSCode workbench in React where the real workbench already exists.

## 10. Immediate Next Moves

If we start now, the first concrete implementation slice should be:

1. Create a Chat visual-system inventory and adopt the first workbench-aligned token pass.
2. Expose current repo/file context inside Chat using the existing session file-context substrate.
3. Upgrade the IOI workbench panes from shallow projections to live runtime-backed summaries.
4. Align palette and context command routing so the same action family uses one runtime path.

That sequence will produce visible product improvement quickly while also strengthening the architectural seam the audit says we should bet on.
