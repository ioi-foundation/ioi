# VS Code OSS × Autopilot Componentization Audit

## 1. Executive summary

Autopilot should converge toward a split architecture where **our runtime remains authoritative** and **Code OSS/OpenVSCode supplies the strongest local code-workbench UX**. The repo already reflects that split more than it might seem at first glance: the durable execution, approval, policy, receipt, skill, and workflow semantics live in our runtime and validator layers, while Workspace now hosts the real OpenVSCode workbench directly inside the Autopilot shell and the Chat/artifact surfaces already share a lighter Code-OSS-derived editor layer. That is the right directional architecture. The highest-value reuse opportunities are not “pull more of VS Code inside Chat,” but rather “reuse editor-core behaviors, codebase-first onboarding flows, inline code-aware interaction patterns, command routing patterns, SCM/diff affordances, and workbench-native view contribution models without surrendering execution semantics.” Code OSS is clearly better at local code interaction design, and at this point that advantage is not subtle: editor navigation, diagnostics, review ergonomics, layout density, command palette expectations, contextual invocation, and general workbench legibility are all stronger than the current Autopilot Chat shell. Our stack is clearly stronger in bounded execution, browser/computer use, approval and policy semantics, typed evidence/receipts, workflow orchestration, and skills as governed runtime assets rather than loose extensions. The most dangerous mistake would be letting VS Code’s extension host or chat affordances become the execution authority for tools, skills, or approvals. The second-most dangerous mistake would be cloning large workbench subsystems into Chat where a lightweight shared editor, a design-system adoption, or a UX pattern would suffice. The best convergence target is a **shared editor substrate plus a shared chat runtime**, with Chat and Workspace remaining distinct shells over the same runtime authority. The strongest near-term bets are native IOI workbench panes backed by real runtime data, codebase-first onboarding/context acquisition parity inside Chat, richer Code-OSS-style review/inspection flows over our evidence model, and deliberate adoption of workbench typography, spacing, iconography, and command grammar across the broader Autopilot shell. The weakest bets are full workbench reuse in Chat, extension-host-led execution semantics, or importing generic marketplace patterns into our skills/tools system. The long-term product should feel like **IOI owns the runtime and product shell, while Code OSS owns the local code-workbench muscle and teaches the rest of the shell how serious developer software should feel**.

## 2. Architectural thesis

The recommended relationship is:

- **Our runtime/harness remains the governing substrate** for execution, policy, approvals, evidence, validation, workflow orchestration, tools, and skills.
- **Code OSS/OpenVSCode remains a UX/workbench substrate** for code-oriented interaction, editor ergonomics, navigation, SCM, terminal, and panel composition.
- **Chat should run on our runtime** everywhere, including inside Code-OSS-style workspace contexts, rather than adopting VS Code’s execution assumptions.
- **Workspace should be the code-first shell**, powered by OpenVSCode for local workbench ergonomics, but fed by our runtime, our workflow graph, our evidence model, and our commands.
- **Editor surfaces should converge onto one shared editor substrate** that can serve both Chat artifact rendering and Workspace code editing without duplicating runtime semantics.
- **Tools and skills should remain our abstraction**, with VS Code contribution patterns used for discovery and invocation UX, not authority or lifecycle.
- **Validation/evidence should remain ours semantically**, while borrowing the best review, diff, problems, output, and inspection affordances from Code OSS.

In practice, that means the long-term stack should look like:

- **Authority plane**: `crates/services`, `crates/validator`, `crates/types`, `crates/api::runtime_harness`
- **Product shell plane**: Autopilot Chat shell and Workspace shell
- **Workbench plane**: OpenVSCode for code-first interaction inside Workspace
- **Shared editor plane**: Code-OSS-derived editor core reused across Workspace and Chat artifact surfaces
- **Bridge plane**: Tauri/runtime adapters and workbench extensions that translate UI intent into our runtime contracts

## 3. Best componentization targets

1. **Shared Code-OSS editor substrate**
   - Source side: both
   - Type: convergence target
   - Why it is attractive: we already have the seam in [codeOss.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/codeOss.ts), [CodeOssEditor.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/CodeOssEditor.tsx), and [WorkspaceEditorPane.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx); it can unify Chat artifact rendering and Workspace editing around one editor-core substrate.
   - Dependency/coupling risk: medium
   - Architectural caveat: this should stop at editor-core and editor-adjacent behavior, not pull full workbench services into Chat.
   - Recommendation: converge both Chat artifact code rendering and Workspace code editing on the shared Code-OSS-derived editor layer, with different capability envelopes.

2. **Workbench-native IOI view contributions**
   - Source side: VS Code OSS
   - Type: component reuse
   - Why it is attractive: [package.json](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/package.json) already proves the right seam via activity-bar containers, views, and commands for `ioi.chat`, `ioi.workflows`, `ioi.runs`, `ioi.artifacts`, `ioi.policy`, and `ioi.connections`.
   - Dependency/coupling risk: low to medium
   - Architectural caveat: current [extension.js](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/extension.js) is no longer merely shell proof; it already builds real editor/workspace context and emits bridge-backed requests, but the resulting panes still feel shallow and webview-oriented compared with native workbench surfaces.
   - Recommendation: treat OpenVSCode contribution points as a first-class host for IOI panes in Workspace, and deepen them until they feel native to the workbench rather than decorative bridge receivers.

3. **Editor context patterns: explain selection, review file, jump to policy, jump to run**
   - Source side: both
   - Type: UX pattern adoption
   - Why it is attractive: VS Code’s context menu, peek, and editor-command ergonomics are materially better than our current ad hoc buttons; our runtime already exposes meaningful targets like `openChatSessionTarget`, `openChatCapabilityTarget`, and `openChatPolicyTarget` in [session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts).
   - Dependency/coupling risk: low
   - Architectural caveat: commands should route into our runtime/session model, not a parallel extension-owned agent flow.
   - Recommendation: adopt the UX model aggressively; keep execution and session semantics ours.

4. **SCM / diff / patch-review ergonomics**
   - Source side: VS Code OSS
   - Type: UX pattern adoption
   - Why it is attractive: OpenVSCode already sets the standard for diff layout, source control grouping, and review ergonomics, while our runtime already has patch/evidence preview logic in [validation_preview.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/validation_preview.rs) and git/file APIs in [workspaceAdapter.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceAdapter.ts).
   - Dependency/coupling risk: medium
   - Architectural caveat: review semantics should remain evidence-aware, not reduced to vanilla git review.
   - Recommendation: borrow the interaction model and paneling; keep our evidence/receipt semantics attached to the review objects.

5. **Command palette interaction model**
   - Source side: both
   - Type: convergence target
   - Why it is attractive: our [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx) already aggregates sessions, skills, runtime catalog, and live tools, but the VS Code command palette interaction grammar is more legible and extensible for power users.
   - Dependency/coupling risk: low
   - Architectural caveat: do not collapse skills/tools into generic extension commands without preserving our richer metadata and runtime semantics.
   - Recommendation: converge on Code-OSS-like interaction and discoverability while preserving our content graph and authority boundaries.

6. **Inspection surfaces for output, problems, traces, and validation**
   - Source side: both
   - Type: convergence target
   - Why it is attractive: Code OSS has better local affordances for panels and issue inspection; our runtime has stronger execution and evidence semantics through [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), and validator/firewall checks.
   - Dependency/coupling risk: medium
   - Architectural caveat: “Problems” and “Output” must not become authoritative evidence containers.
   - Recommendation: borrow panel models and drilldown ergonomics, but keep canonical evidence in our persisted artifacts.

7. **Inline chat / code-aware assistant invocation**
   - Source side: VS Code OSS
   - Type: UX pattern adoption
   - Why it is attractive: inline chat is a superior entry point for file/selection-centric work, especially compared to bouncing users out into a separate chat shell.
   - Dependency/coupling risk: medium
   - Architectural caveat: the runtime behind inline chat must be ours; otherwise we blur authority and duplicate task state.
   - Recommendation: mount Code-OSS-style inline chat affordances onto our session/runtime APIs rather than adopting VS Code’s agent backend.

8. **Workspace session persistence for editor state and layout**
   - Source side: our stack
   - Type: component reuse
   - Why it is attractive: we already have workspace session state and persistence seams in [useWorkspaceSession.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/useWorkspaceSession.ts) and [WorkspaceHost.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/WorkspaceHost.tsx).
   - Dependency/coupling risk: low
   - Architectural caveat: do not re-implement state the upstream workbench already persists better in Workspace mode.
   - Recommendation: reuse our substrate persistence for Chat/lightweight editors and let OpenVSCode own full workbench state where appropriate.

9. **OpenVSCode shell inside Chat**
   - Source side: VS Code OSS
   - Type: not worth reusing
   - Why it is attractive: superficial parity
   - Dependency/coupling risk: high
   - Architectural caveat: it would import workbench weight and boundary confusion into a surface that should remain fast and artifact-focused.
   - Recommendation: avoid.

10. **Extension host as tool/skill runtime**
    - Source side: VS Code OSS
    - Type: not worth reusing
    - Why it is attractive: standard plugin model
    - Dependency/coupling risk: very high
    - Architectural caveat: it directly conflicts with our governed tools/skills/runtime authority model.
    - Recommendation: avoid completely.

## 4. Area-by-area audit

### Editor and artifact surfaces

**What Code OSS does well**

- best-in-class editor interaction model
- tab groups, breadcrumbs, diagnostics, hover/peek, go-to-definition, references, and patch/diff ergonomics
- strong diff presentation and code navigation expectations

**What our stack does well**

- shared editor-core abstraction already exists via [CodeOssEditor.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/CodeOssEditor.tsx)
- workspace-aware editor pane already binds language snapshots, definitions, references, code actions, and notebooks in [WorkspaceEditorPane.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx)
- Chat artifact source rendering already uses the lighter editor substrate in [ArtifactSourceWorkbench.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ArtifactSourceWorkbench.tsx)

**What should be reused**

- editor-core substrate
- editor affordances like hover/peek/diagnostics
- diff/review layout patterns

**What should only inspire UX**

- workbench tab-group management inside Chat
- full editor-group orchestration for artifact previews

**What should remain ours**

- artifact semantics, evidence attachment, validation status, receipt-linked rendering
- the split between lightweight artifact rendering in Chat and full editing in Workspace

**What should be avoided**

- embedding the full OpenVSCode shell into Chat artifact rendering
- duplicating editor runtime semantics in both Chat and Workspace

### Chat and assistant UX

**What Code OSS does well**

- code-adjacent invocation points
- inline chat and selection-aware prompting
- naturally contextual command invocation from file, selection, diff, and output
- codebase-first orientation where the repository, open editors, explorer, search, and terminal all reinforce the same working context

**What our stack does well**

- our runtime-backed session model is richer and more governed than generic editor chat
- [use-session-composer.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/use-session-composer.ts) explicitly handles gate blocks, sudo pauses, clarification pauses, local history, and session continuation
- [session-runtime.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/session-runtime.ts) and [assistant-session-runtime-types.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/assistant-session-runtime-types.ts) already expose explicit shell targeting and runtime APIs
- Chat has broader runtime reach than Code OSS agent chat, but its current shell is still less legible, less contextual, and less codebase-first than the workbench UX users compare it against

**What should be reused**

- inline chat UX
- code-aware composer invocation patterns
- editor/context action entry points
- codebase-first onboarding and context acquisition patterns, especially around “what repo am I in, what file am I looking at, what should I inspect next”

**What should only inspire UX**

- result rendering and panel choreography from VS Code agent surfaces

**What should remain ours**

- default chat runtime
- session lifecycle
- pause/resume/gate semantics
- clarification and approval flows

**What should be avoided**

- letting VS Code’s chat assumptions own task/session state
- treating extension-host chat as canonical

### Visual system and typography

**What Code OSS does well**

- typography, density, spacing rhythm, and iconography tuned for long developer sessions
- an interaction language where panels, trees, tabs, actions, breadcrumbs, and command surfaces all feel like one family
- restrained chrome that still conveys strong hierarchy and focus

**What our stack does well**

- product-level shell affordances outside the IDE, including chat, workflows, policy, and capabilities
- flexibility to express runtime-specific concepts that do not naturally fit inside workbench chrome

**What should be reused**

- font stack and typographic proportions where licensing/distribution permits
- spacing, control sizing, icon density, hover/focus treatment, and panel rhythms from the workbench
- the general visual seriousness of Code OSS across the rest of Autopilot

**What should only inspire UX**

- shell-wide visual language; Chat should not pretend to be the entire workbench

**What should remain ours**

- outer shell IA and product-specific concepts
- places where our runtime semantics need stronger affordances than generic IDE chrome provides

**What should be avoided**

- preserving a bespoke Autopilot visual language just because it is already there
- carrying forward low-density chat chrome when the workbench has already proven the better answer

### Agent runtime and tool execution

**What Code OSS does well**

- lightweight local command invocation patterns
- editor-integrated feedback loops
- terminal-first affordances and interruption idioms

**What our stack does well**

- durable execution runtime with explicit lifecycle and receipt semantics in [crates/services/src/agentic/runtime/README.md](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/README.md)
- policy and approval enforcement in [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs)
- typed resume/approval flows, transcript continuity, and worker lifecycle
- richer tools/skills abstraction and governed execution pathways

**What should be reused**

- action/result UX patterns around progress, interruption, contextual invocation, and local feedback

**What should only inspire UX**

- terminal/task progress UI
- inline action result presentation

**What should remain ours**

- tool execution authority
- browser/computer use
- interruption legality
- action settlement and evidence

**What should be avoided**

- extension-host-led execution semantics
- opaque local task runners becoming a parallel agent runtime

### Browser/computer use

**What Code OSS does well**

- local terminal and file-context adjacency for development tasks

**What our stack does well**

- deep browser/computer-use primitives through [IOI Browser Driver README](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/README.md) and browser-use DOM ops
- explicit firewall and sandbox concerns
- deterministic CDP-backed control rather than generic editor automation assumptions

**What should be reused**

- contextual invocation patterns from files/terminal/editor into browser/computer actions

**What should only inspire UX**

- paneling and progress display for automation tasks

**What should remain ours**

- browser/computer use runtime
- safety and policy boundaries
- evidence generation for automation actions

**What should be avoided**

- adopting a weaker “agent can click around” model without our firewall/evidence semantics

### Validation, review, and evidence

**What Code OSS does well**

- diff review and problems/output visibility
- panel navigation and inspection ergonomics

**What our stack does well**

- approval grants, policy decision records, settlement bundles, validator checks, and PII review contracts through [action.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/types/src/app/action.rs), [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), [validator firewall](/home/heathledger/Documents/ioi/repos/ioi/crates/validator/src/firewall/mod.rs), and [review_contract.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/pii/src/review_contract.rs)
- explicit distinction between authoritative artifacts and non-authoritative events

**What should be reused**

- diff inspection UX
- problems/output panel ergonomics
- trace/log drilldown patterns

**What should only inspire UX**

- review decorations and issue surfaces for evidence/receipt-linked outcomes

**What should remain ours**

- evidence model
- approval semantics
- settlement semantics
- validation verticals and canonical artifacts

**What should be avoided**

- treating logs or panel state as authoritative proof
- replacing evidence semantics with generic IDE diagnostics

### Workflow and orchestration

**What Code OSS does well**

- task list mental models
- paneling and navigation among concurrent activities

**What our stack does well**

- workflow discovery and orchestration in [workspace_workflows.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workspace_workflows.rs)
- richer workflow semantics in kernel/workflow commands and runtime activity models
- operator step/status shaping in the chat pipeline and task state modules

**What should be reused**

- task-tree, outline, and panel visibility patterns

**What should only inspire UX**

- run tree, step state, retry/repair inspection, and workflow navigation patterns

**What should remain ours**

- workflow semantics
- merge/retry/repair meanings
- bounded execution state

**What should be avoided**

- collapsing workflows into generic task lists with no receipt/policy semantics

### Extensions, tools, and skills

**What Code OSS does well**

- contribution points
- commands
- activity-bar views
- discoverable workbench integration model

**What our stack does well**

- skills are governed lifecycle-managed assets with reliability and archival semantics in [skill_registry.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/skill_registry.rs)
- tools/skills have richer runtime eligibility and policy posture than a generic extension marketplace
- command palette already aggregates sessions, runtime catalog, skills, and live tools in [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx)

**What should be reused**

- command contribution and discovery grammar
- workbench view contribution seams

**What should only inspire UX**

- palette ranking/presentation
- extension-like discoverability for skills

**What should remain ours**

- skills and tool registry
- lifecycle, eligibility, reliability scoring, policy incidents

**What should be avoided**

- treating skills as just VS Code extensions
- moving tool authority into extension activation code

### Workbench shell boundary

**What Code OSS does well**

- code-first shell
- local developer legibility
- strong workspace mental model

**What our stack does well**

- product-level shell and navigation are broader than an IDE
- Chat, workflows, runs, policy, and capabilities live naturally outside pure IDE chrome in [useChatWindowController.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/useChatWindowController.ts)

**What should be reused**

- Workspace as the code-first shell, powered by OpenVSCode via [workspace_ide.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/workspace_ide.rs), [directWorkspaceWorkbenchHost.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/directWorkspaceWorkbenchHost.ts), [WorkspaceShell.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/WorkspaceShell.tsx), and [OpenVsCodeDirectSurface.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/OpenVsCodeDirectSurface.tsx)

**What should only inspire UX**

- shell-local panel organization outside Workspace

**What should remain ours**

- outer product shell
- Chat as lightweight conversation-first shell
- cross-surface navigation

**What should be avoided**

- making OpenVSCode the top-level product shell
- mounting full workbench chrome into Chat

### Runtime authority boundaries

**What Code OSS does well**

- local interaction ergonomics
- contribution and command models

**What our stack does well**

- explicit runtime and validator authority boundaries
- approval grants and authority verification
- policy-decision records
- settlement receipts and postcondition/evidence semantics
- local UI not being allowed to mint approval authority, as documented in [governance.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/governance.rs)

**What should be reused**

- only the UX shell around authority-relevant actions

**What should only inspire UX**

- approval/review interaction patterns
- execution inspection layouts

**What should remain ours**

- anything that changes state, authorizes execution, settles execution, or proves consequences

**What should be avoided**

- importing VS Code runtime assumptions that treat UI state, extension state, or logs as execution authority

## 5. Specific findings

1. **OpenVSCode is already correctly positioned as a workspace engine, not a product shell.**
   - [workspace_ide.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/workspace_ide.rs) launches `openvscode-server` as the local workbench runtime, and the production direct path now hosts it inside the Autopilot Workspace rect through [directWorkspaceWorkbenchHost.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/directWorkspaceWorkbenchHost.ts), [WorkspaceShell.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/WorkspaceShell.tsx), and [OpenVsCodeDirectSurface.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/OpenVsCodeDirectSurface.tsx). This is the right shell boundary: Workspace is code-first and heavy; Chat remains separate.

2. **Our current IOI OpenVSCode extension is a good seam and more real than this audit previously gave it credit for, but it is not yet a strong product surface.**
   - [package.json](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/package.json) defines the right containers and commands, and [extension.js](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/openvscode-extension/ioi-workbench/extension.js) already gathers editor/workspace context and emits bridge-backed requests such as `chat.explainSelection`, `chat.reviewFile`, `chat.reviewRun`, and `evidence.open`. The opportunity is not “replace this seam,” but “deepen it until the panes feel workbench-native rather than bridge-fed.”

3. **We already have the right shared editor abstraction; we should lean into it.**
   - [CodeOssEditor.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/CodeOssEditor.tsx), [WorkspaceEditorPane.tsx](/home/heathledger/Documents/ioi/repos/ioi/packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx), and [ArtifactSourceWorkbench.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatShellWindow/components/ArtifactSourceWorkbench.tsx) show a healthy split: lightweight editor rendering in Chat, richer pane behavior in Workspace, same editor substrate.

4. **Our workspace backend is stronger than any generic “just let VS Code do it” story.**
   - [workspaceAdapter.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceAdapter.ts) already exposes file, LSP, git, diff, terminal, and workspace snapshot operations to the UI. That means we should not import large extra workbench subsystems where our adapter already gives a bounded seam.

5. **The chat runtime is already strongly runtime-aware and pause-aware in ways Code OSS does not provide.**
   - [use-session-composer.ts](/home/heathledger/Documents/ioi/repos/ioi/packages/agent-ide/src/runtime/use-session-composer.ts) explicitly blocks submission on gate, pending request hashes, sudo, and clarification waits. This is richer than generic “send prompt to assistant” editor chat.

6. **The authoritative execution semantics are decisively ours.**
   - [runtime README](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/README.md), [firewall_policy.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/firewall_policy.rs), [receipt_emission.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/runtime/service/handler/execution/execution/receipt_emission.rs), and [validator firewall](/home/heathledger/Documents/ioi/repos/ioi/crates/validator/src/firewall/mod.rs) make it clear that approval, policy, determinism, and settlement live in our runtime/validator plane, not in UI or workbench state.

7. **Browser/computer use is a clear “stay ours” domain.**
   - [IOI Browser Driver README](/home/heathledger/Documents/ioi/repos/ioi/crates/drivers/src/browser/README.md) and browser-use modules show deeper execution and firewall integration than a generic editor agent environment.

8. **Skills are not extensions in disguise.**
   - [skill_registry.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/services/src/agentic/skill_registry.rs) gives skills lifecycle, reliability, eligibility, and archival semantics. That is fundamentally richer than a plain extension/contribution model and should remain separate.

9. **Our command palette content model is richer than VS Code’s, but the interaction model is weaker.**
   - [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx) already includes sessions, projects, skills, runtime catalog, and live tools. This is strong content, but the UX can still converge toward Code-OSS-grade discoverability and flow.

10. **Code OSS agent UX is materially ahead of the current Autopilot Chat shell, even if our runtime may already be ahead underneath it.**
   - [ChatWindowMainContent.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/components/ChatWindowMainContent.tsx), [ChatIdeHeader.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/components/ChatIdeHeader.tsx), and [ChatLocalActivityBar.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/windows/ChatWindow/components/ChatLocalActivityBar.tsx) make the Chat shell visibly custom and product-specific. That flexibility is useful, but the workbench still wins on density, navigation coherence, contextual entry points, and overall “developer software” legibility.

11. **Codebase-first onboarding/context parity is now a likely near-term target, not a speculative idea.**
   - [workspaceAdapter.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceAdapter.ts), [directWorkspaceWorkbenchHost.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/directWorkspaceWorkbenchHost.ts), and [workspaceRuntimeNavigation.ts](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/services/workspaceRuntimeNavigation.ts) show that we already have the ingredients for file-aware, repo-aware, context-rich handoff between workbench state and our runtime. The remaining gap is productizing those signals in the Chat shell with the same inevitability that the workbench provides.

12. **Workflow discovery already has a workspace-native seam.**
    - [workspace_workflows.rs](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src-tauri/src/kernel/workspace_workflows.rs) discovers workspace workflows from repo files. That is a strong basis for native workbench workflow panes and command palette contributions without changing runtime semantics.

13. **Our chat/artifact layer already produces code-review-adjacent primitives that should be surfaced better.**
    - [validation_preview.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/chat/generation/validation_preview.rs) and related generation/finalize modules indicate we already have rich validation-preview semantics that should likely adopt stronger Code-OSS-style review UX.

14. **The runtime harness naming itself is converging toward a neutral substrate.**
    - [runtime_harness.rs](/home/heathledger/Documents/ioi/repos/ioi/crates/api/src/runtime_harness.rs) re-exports chat/runtime functionality under a more neutral harness frame, which supports the long-term thesis that Chat and Workspace should share the runtime substrate even if they differ in UX shell.

## 6. Convergence map

### Shared editor substrate

- **Converge**
  - Chat artifact source previews
  - diff/patch review editors
  - lightweight inline code edits
  - Workspace editor-core behavior
- **Why**
  - we already have the shared seam and should avoid dual editor stacks
- **Do not converge**
  - full workbench services into Chat

### Shared chat runtime

- **Converge**
  - default chat in Workspace should call our runtime/session APIs
  - inline chat and file/selection review commands should route into `session-runtime.ts` and `runtime_harness`
- **Why**
  - this preserves one agent runtime and one lifecycle model
- **Do not converge**
  - extension-host-owned task state or approval state

### Shared rendering surfaces

- **Converge**
  - code previews, diffs, validation previews, evidence-linked review surfaces
  - output/log/trace drilldowns where data comes from our runtime
- **Why**
  - it prevents duplicate render logic and improves coherence
- **Do not converge**
  - full workbench panels into Chat, or Chat cards into Workspace where native panes are better

### Shared tool/skill abstractions

- **Converge**
  - discoverability grammar, command invocation patterns, and contextual entry points
- **Keep separate**
  - skills registry, lifecycle, reliability, policy posture
  - tool execution semantics
- **Why harmful if forced**
  - treating skills as extension contributions would erase governance and benchmarking semantics

### Shared validation primitives

- **Converge**
  - inspection and drilldown UX around diffs, receipts, and output
- **Keep separate**
  - canonical artifacts: approval grants, policy decision records, settlement bundles, postcondition proofs
- **Why harmful if forced**
  - “Problems” and logs are not proof, and must not become settlement authority

### Convergence that would be harmful

- full OpenVSCode shell inside Chat
- extension host as execution/runtime authority
- generic marketplace semantics for skills/tools
- editor UI becoming the place where approval/policy truth lives

## 7. Near-term next sprint targets

1. **Adopt the workbench visual system across the rest of Autopilot**
   - Why now: the real workbench is already the strongest-looking part of the product, and the contrast with the current Chat shell is becoming a product liability.
   - Expected payoff: high
   - Implementation complexity: medium
   - Risk: low to medium
   - Whether it is UX-facing, architecture-facing, or both: primarily UX-facing

2. **Back the OpenVSCode IOI panes with real runtime data**
   - Why now: the extension seam already exists and is visibly shallow today.
   - Expected payoff: high
   - Implementation complexity: medium
   - Risk: medium
   - Whether it is UX-facing, architecture-facing, or both: both

3. **Build codebase-first onboarding/context acquisition parity into Chat**
   - Why now: Workspace already proves the right repo/file/context posture; Chat should stop feeling comparatively ungrounded when the user is working inside a codebase.
   - Expected payoff: high
   - Implementation complexity: medium
   - Risk: medium
   - Whether it is UX-facing, architecture-facing, or both: both

4. **Add editor-context actions that route into our runtime**
   - Why now: we already have `ioi.chat.explainSelection`, `ioi.chat.reviewFile`, and shell targeting APIs; the missing piece is real end-to-end routing and richer results.
   - Expected payoff: high
   - Implementation complexity: medium
   - Risk: low to medium
   - Whether it is UX-facing, architecture-facing, or both: both

5. **Unify command palette interaction with Code-OSS-like grammar while preserving our richer content**
   - Why now: low-risk UX win over already-valuable content in [CommandPalette.tsx](/home/heathledger/Documents/ioi/repos/ioi/apps/autopilot/src/components/CommandPalette.tsx)
   - Expected payoff: high
   - Implementation complexity: medium
   - Risk: low
   - Whether it is UX-facing, architecture-facing, or both: both

6. **Build an evidence/validation inspection pane using Code-OSS review patterns**
   - Why now: our evidence and validation model is strong, but the UX is weaker than the semantics deserve.
   - Expected payoff: high
   - Implementation complexity: medium to high
   - Risk: medium
   - Whether it is UX-facing, architecture-facing, or both: both

7. **Make Workspace-native workflow/runs panes real instead of presentational**
   - Why now: workflow discovery and runtime activity models already exist; users should not have to leave Workspace to inspect them.
   - Expected payoff: medium to high
   - Implementation complexity: medium
   - Risk: medium
   - Whether it is UX-facing, architecture-facing, or both: both

8. **Adopt stronger Code-OSS-style diff/review interaction for artifact previews**
   - Why now: we already render artifact source and validation previews; the missing piece is interaction quality.
   - Expected payoff: medium
   - Implementation complexity: medium
   - Risk: low
   - Whether it is UX-facing, architecture-facing, or both: primarily UX-facing

## 8. Long-term bets

1. **Inline chat in Workspace backed entirely by our runtime**
   - Attractive because it would make the Workspace shell feel native and powerful without splitting runtime authority.
   - Not next-sprint because it requires careful session, threading, and evidence integration.

2. **A unified evidence-aware review substrate across Chat and Workspace**
   - Attractive because it would collapse multiple review/read surfaces into one strong inspection model.
   - Not next-sprint because it crosses editor, artifact, runtime, and validation boundaries.

3. **Native OpenVSCode panes for policy, approvals, and receipts**
   - Attractive because it would make governance visible in the same place developers act.
   - Not next-sprint because it must not weaken authority boundaries or over-simplify the semantics.

4. **Command/context convergence between Chat shell and Workspace shell**
   - Attractive because it would make the product feel like one substrate with two shells.
   - Not next-sprint because it requires harmonizing navigation and contribution models.

5. **A shared runtime-backed activity model for runs, workflows, evidence, and artifacts**
   - Attractive because it would unify our product-level activity graph with workbench-native panes.
   - Not next-sprint because it needs careful data contracts and performance design.

## 9. Non-targets

- **Full workbench reuse in Chat**
  - Tempting because it promises parity, but it imports too much weight and collapses the Chat/Workspace boundary.

- **Extension host as authoritative execution runtime**
  - Tempting because it is a standard plugin model, but it conflicts directly with our governed runtime.

- **Treating skills as extensions**
  - Tempting because contribution models are familiar, but it erases lifecycle, reliability, and policy semantics.

- **Replacing evidence/receipt semantics with generic problems/logs/output**
  - Tempting because IDE users understand those panels, but they are not authoritative proof artifacts.

- **Rebuilding Code OSS chrome in React where we already have the real workbench**
  - Tempting because custom UI feels flexible, but it is wasted effort and usually lower quality than the upstream workbench.

- **Letting VS Code’s local UX imply weaker governance**
  - Tempting because it feels fast and natural, but it would blur the constitutional boundary that makes our runtime valuable.

## 10. Final recommendation

Use Code OSS/OpenVSCode as the **code-workbench substrate**, not the execution authority. Keep Chat and Workspace as distinct shells over one runtime/harness, with Workspace optimized for code-first work and Chat optimized for conversation-first, artifact-aware work. Converge aggressively on a shared editor substrate, Code-OSS-grade interaction patterns, native workbench panes for IOI concepts, editor/selection/terminal commands that route into our runtime, and a broader Autopilot visual system that learns unapologetically from the workbench’s typography, density, and command grammar. Do not converge on extension-host-led execution, generic marketplace semantics for skills, or full workbench reuse inside Chat. The next move should be to make the existing OpenVSCode IOI panes real, build codebase-first onboarding/context parity in Chat, wire editor-context actions to our runtime/session APIs, and build a better evidence/validation inspection surface using Code-OSS review idioms. At the same time, we should keep bounded execution, approvals, browser/computer use, evidence, validation, and workflow semantics authoritative in our runtime and validator plane. The product should feel like **IOI owns the state, authority, and orchestration**, while **Code OSS contributes the best local code interaction model and the strongest visual grammar wherever that model is genuinely stronger**.

| Area | Opportunity | Type | Value | Complexity | Risk | Recommendation |
|---|---|---|---|---|---|---|
| Editor/artifacts | Shared Code-OSS editor substrate for Chat and Workspace | Converge | High | Medium | Medium | Converge on one editor-core substrate, but keep Chat lightweight |
| Editor/artifacts | Full OpenVSCode shell in Chat | Avoid | Low | High | High | Do not reuse |
| Chat UX | Inline chat and code-context invocation patterns | Pattern | High | Medium | Medium | Adopt the UX, back it with our runtime |
| Chat UX | VS Code chat runtime semantics | Avoid | Low | High | High | Keep our runtime authoritative |
| Agent runtime | Progress/interruption/task UX patterns | Pattern | Medium | Medium | Low | Borrow interaction design only |
| Agent runtime | Execution authority in extension host | Avoid | Low | High | High | Never let extension state become authoritative |
| Browser/computer use | Editor/terminal-to-automation invocation affordances | Pattern | Medium | Medium | Medium | Reuse entry patterns, keep execution ours |
| Browser/computer use | Generic IDE automation substrate | Avoid | Low | High | High | Keep browser/computer use in our drivers/runtime |
| Validation/review | Evidence-aware diff/review panes | Converge | High | Medium | Medium | Use Code-OSS review UX over our evidence model |
| Validation/review | Problems/logs as settlement proof | Avoid | Low | Low | High | Keep canonical artifacts authoritative |
| Workflow/orchestration | Native Workspace runs/workflows panes | Reuse | High | Medium | Medium | Back existing workbench contribution seams with live runtime data |
| Tools/skills/extensions | Command contribution and palette grammar | Pattern | High | Medium | Low | Adopt VS Code discoverability patterns |
| Tools/skills/extensions | Skills as extensions | Avoid | Low | Medium | High | Keep skills as governed runtime assets |
| Workbench boundary | OpenVSCode as Workspace engine | Reuse | High | Medium | Medium | Continue using OpenVSCode in Workspace only |
| Workbench boundary | Outer IOI shell as product navigation | Converge | High | Medium | Low | Keep IOI shell outside the workbench |
| Runtime authority | Policy/approval/evidence in our runtime | Converge | High | Medium | Low | Preserve our authority plane as the single source of truth |
