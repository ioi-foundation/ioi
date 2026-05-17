# Phase 5 Early Connector Expansion Master Guide

Owner: connectors-tools / daemon runtime / wallet.network / Autopilot / workflow compositor / computer-use

Status: gated by P0 lifecycle clarity / Workstream 1 may proceed as proof sample

Created: 2026-05-15

## Executive Verdict

Phase 5 proves Autopilot can operate real production software safely without
jumping straight to money-moving commerce. The Phase 4.5 capability authority
gate has reached Definition of Ready for local, proposal-first, read-only,
draft-only, and fixture-backed computer-use lanes.

Before broad connector expansion, Phase 5 is gated by the P0 lifecycle clarity
leg in
`internal-docs/plans/autopilot-lifecycle-clarity-over-ioi-primitives-master-guide.md`.
The core assertion is:

> Autopilot needs ADK/Gemini-level lifecycle clarity over IOI's stronger
> primitives.

Workstream 1 filesystem/Git proposal-first mutation may proceed as the canonical
proof sample for that lifecycle shape. Broader connector breadth should wait
until autonomous-system package shape, terminology boundaries, package
readiness, and evaluation-as-default are locked.

The target is not "more integrations." The target is:

> Real software operation through typed, authority-scoped, proposal-first,
> receipt-producing capabilities that can be composed in workflows and observed
> in Autopilot without leaking secrets or bypassing policy.

## Entry Gate

Phase 5 Workstream 1 may begin as the P0 lifecycle proof because all of these
are now true:

- connector/tool registry exposes complete `RuntimeToolContract` metadata;
- model routes expose capability, policy, BYOK, readiness, and receipt metadata;
- wallet-core-lite brokers connector credentials and model provider keys;
- Policy/Settings have been refreshed into an Authority Center;
- workflows bind model/tool capabilities rather than provider-specific branches;
- task-scoped GUI/browser harness can launch Autopilot or another approved
  local target with an isolated profile and cleanup receipts;
- Playwright has been validated as the isolated GUI/browser validation harness
  and is queued as the preferred first-class adapter candidate for Workstream 2;
- live actions fail closed without contract, readiness, grant, approval when
  required, idempotency posture, and receipt behavior;
- targeted build, daemon, SDK, workflow GUI, authority/settings, computer-use,
  and live Playwright clickthrough validation passed on 2026-05-17.

Additional P0 lifecycle gate before broader connector expansion:

- Autonomous System Package is asserted as the primary build artifact;
- autonomous-system manifest/profile shape is documented as its runtime
  contract/profile;
- Agent/Worker/Skill/Tool/Connector/Workflow/Harness/Capability/Policy/Trace/
  Receipt/Runtime terminology is locked;
- lifecycle verbs are locked: compose, bind, simulate, authorize, run, verify,
  inspect receipts, package, deploy, promote, improve;
- Workflow Composer distinguishes run readiness from package, evaluation,
  deployment, and promotion readiness;
- one canonical repo-maintenance autonomous-system proof sample exists;
- fixture evals and expected receipts exist for the proof sample;
- old workflows project into the package/lifecycle lens without breaking.

External constraints that still apply:

- live Google Workspace/mail, provider-hosted models, and external connector
  smokes require explicit credentials and wallet grants;
- high-risk commerce and irreversible external publication remain out of scope;
- first-class durable Playwright runtime receipts are part of Workstream 2, not
  a blocker for Workstream 1.

## Canonical Sources

- `docs/roadmap.md`
- `docs/architecture/components/connectors-tools/doctrine.md`
- `docs/architecture/components/connectors-tools/contracts.md`
- `docs/architecture/components/wallet-network/doctrine.md`
- `docs/architecture/components/wallet-network/api-authority-scopes.md`
- `docs/architecture/components/model-router/doctrine.md`
- `docs/architecture/components/daemon-runtime/doctrine.md`
- `docs/architecture/products/autopilot/local-app-workflow-canvas.md`
- `docs/plans/policy-platform-execution-master-guide.md`
- `docs/plans/isolated-computer-providers-master-guide.md`

## Doctrine

- No effectful connector or tool without a contract.
- No raw connector secret or BYOK key in workflow manifests, product settings,
  logs, packages, or receipts.
- No high-risk action without wallet authority, approval, and receipt binding.
- Draft/proposal-first beats direct external mutation.
- Local creative tools can run earlier because they produce local artifacts, but
  they still need schemas, artifacts, and receipts.
- Browser/computer-use and shell/sandbox hardening use the same authority and
  receipt substrate as connectors.
- React Flow remains a configurable authoring projection. Runtime truth stays in
  daemon contracts, wallet grants, policies, events, and receipts.

## Completion Dashboard

| Lane | Goal | Initial posture | Done when |
| --- | --- | --- | --- |
| Filesystem/Git proposal-first mutation | Safe local code/file changes with previews and rollback. | Start first; Phase 4.5 gate passed. | Reads, diffs, patch proposals, branch ops, and writes are policy-bound and receipted. |
| Browser/computer-use hardening | Operate web apps through native browser, visual GUI, and sandbox lanes. | Continue from existing computer-use leg. | Actions have observation, target, proposal, policy, verification, trajectory, and cleanup receipts. |
| Local shell/sandbox hardening | Execute commands with least privilege and clear containment. | Must share policy envelope. | Shell actions carry sandbox profile, risk, approval, stdout/stderr artifacts, and cleanup. |
| Blender connector | Local creative connector proof. | Early safe connector. | Generate/edit/render/export through typed tools with artifact receipts. |
| FreeCAD/CAD connector | Local CAD proof. | Early safe connector. | Create/edit/validate/export CAD artifacts with schemas and receipts. |
| Google Workspace/mail read-only | Production data read proof. | Requires wallet credential path. | Read-only Drive/Gmail/Calendar actions use scopes, redaction, mapping, and receipts. |
| Draft-only outputs | External communication preparation without send authority. | Safer than sends. | Email/calendar/doc drafts are previewed, approval-gated, and not sent/published by default. |
| Connector quality and registry feedback | Tool outcomes improve routing and readiness. | Later in Phase 5. | Tool quality telemetry feeds registry without becoming hidden authority. |

## Connector Risk Tiers

| Tier | Examples | Default posture |
| --- | --- | --- |
| Tier 1: safe read/local output | file read, Git read, browser inspect, Blender render/export, FreeCAD export, read-only Drive/Gmail/Calendar | Usually no approval; still receipted. |
| Tier 2: reversible local write/draft | file write, Git patch proposal, Blender scene edit, CAD edit, email draft, calendar draft, doc draft | Preview plus confirmation when policy requires. |
| Tier 3: external communication | send email, post Slack, GitHub issue/comment, calendar invite | Approval required unless narrowly pre-granted. |
| Tier 4: commerce/irreversible | submit order, book travel, pay invoice, transfer funds | Deferred. Mandatory approval, budget, and receipt binding when eventually implemented. |

## Target Runtime Flow

Every Phase 5 live action should follow:

```text
resolve capability
-> load contract and readiness
-> request or verify authority grant
-> evaluate policy
-> dry-run or proposal preview
-> request approval when required
-> execute through adapter
-> validate output schema
-> emit action and verification receipts
-> record artifact refs and redaction posture
-> update run/workflow history
```

If any step cannot complete, the action fails closed with recovery guidance.

## Reference Method: Task-Scoped Autopilot GUI Run

The Phase 5 browser/computer-use lane should preserve the methodology proved by
the recent live audit session:

1. Route the request to the GUI/browser-use lane because the target was an
   Autopilot product surface, not a connector API call.
2. Start the local Autopilot target through an explicit command and readiness
   probe.
3. Open the target through an owned browser session with an isolated profile or
   user-data-dir, never the user's everyday browser profile.
4. Capture screenshots, observations, logs, and run notes outside git or under
   ignored evidence paths.
5. Inspect or click through the real UI as a user would, choosing Policy,
   Settings, Workflow, or other surfaces by target state.
6. Clean up the dev server, browser process, temporary profile, and transient
   artifacts.
7. Report residual dirty worktree state separately from generated evidence.

The production target is the same behavior as a first-class runtime harness:
environment selection, lease, observation, action, verification, trajectory, and
cleanup receipts around the whole GUI session.

Playwright should be included in this reference method as a preferred adapter
candidate for web and local-web-app tasks. Its browser contexts, locator model,
auto-wait/actionability checks, tracing, screenshots, console/network logs, and
CDP escape hatch are all valuable. IOI should use those strengths without
letting Playwright become a second runtime or a shadow source of truth.

## Workstreams

### Workstream 1: Filesystem And Git Proposal-First Mutation

Goal: local file and Git operations become the first safe proof of production
software control.

Minimum tools:

- `fs.read`;
- `fs.search`;
- `fs.write_proposal`;
- `fs.apply_patch`;
- `git.status`;
- `git.diff`;
- `git.branch_proposal`;
- `git.commit_proposal`;
- `git.apply_with_receipt`.

Required behavior:

- reads are receipted when they touch governed resources;
- writes produce preview artifacts before mutation;
- patch application is idempotent or carries a clear replay policy;
- branch/commit operations are proposal-first unless authority grants allow
  direct mutation;
- rollback or restore artifacts are available for local writes.

Validation:

- unit tests for contract schema and output validation;
- integration tests for proposal, approval, apply, receipt, and rollback;
- GUI workflow run showing diff preview, approval, application, and receipt.

### Workstream 2: Browser And Computer-Use Hardening

Goal: mature the browser/computer-use harness as a Phase 5 connector lane.

Required behavior:

- native browser use remains CDP/DOM/AX/selector-aware where possible;
- Playwright is supported as an adapter when it improves reliability,
  cross-browser coverage, tracing, locators, or task-scoped isolation;
- Playwright actions compile to IOI `ActionProposal` and `ComputerAction`
  records before execution;
- Playwright traces, screenshots, videos, console logs, network logs, and action
  errors are retained as IOI artifacts and evidence refs;
- visual GUI fallback uses screenshot, accessibility, SoM, and coordinate
  safety;
- the harness can start approved local targets such as Autopilot with a
  readiness probe, URL binding, and shutdown policy;
- owned browser sessions use task-scoped profiles or user-data-dirs so local GUI
  validation never contaminates the user's browser state;
- sandboxed/isolated environments use the provider registry from the isolated
  computer providers guide;
- evidence paths are explicit and ignored or outside git by default;
- every action goes through `ActionProposal`, policy, `ComputerAction`,
  verification, and trajectory recording;
- cleanup receipts cover target app process, browser process, profile
  directory, server port, and retained evidence;
- commit gates pause before external side effects.

Validation:

- browser run smoke with target index and verification receipt;
- Playwright smoke: launch isolated context, navigate to approved target, use a
  role/text locator, capture trace/screenshot, execute one bounded action,
  verify state, and close context/browser cleanly;
- Playwright degraded-readiness test when browsers or dependency install are
  unavailable;
- visual fallback run smoke with coordinate safety and drift checks;
- Autopilot GUI smoke: launch target app, open isolated browser profile, inspect
  Policy/Settings/Workflow surfaces, capture screenshots, and clean up;
- profile isolation test proving default browser history/cookies/profile files
  are untouched;
- sandbox/local-container smoke when provider is available, or fail-closed
  provider readiness when unavailable;
- Autopilot run trace reveals the glass-box flow.

### Workstream 3: Local Shell And Sandbox Hardening

Goal: shell execution is useful for production workflows without ambient power.

Required behavior:

- commands carry sandbox profile, working directory, env policy, network policy,
  timeout, and cleanup behavior;
- commands with mutation risk require approval unless covered by a narrow grant;
- stdout/stderr and produced files become artifacts with redaction policy;
- package installs and network access are explicit authority changes;
- failed commands produce recovery receipts rather than silent retries.

Validation:

- read-only command smoke;
- write command approval smoke;
- network/package-install blocked smoke;
- artifact and cleanup receipt tests.

### Workstream 4: Blender Connector

Goal: prove a local creative connector can produce real artifacts through typed
tools.

Minimum tools:

- `blender.discover`;
- `blender.open_scene`;
- `blender.create_scene`;
- `blender.apply_script_proposal`;
- `blender.render_preview`;
- `blender.export_asset`;
- `blender.validate_scene`.

Required behavior:

- connector discovery reports installed version and executable path without
  running untrusted scripts;
- generated scripts are proposal-first;
- renders and exports produce artifact refs and receipts;
- file writes obey workspace and authority policy.

Validation:

- headless fixture if Blender is unavailable;
- live smoke when Blender exists locally;
- workflow graph can render preview and export artifact with receipts.

### Workstream 5: FreeCAD/CAD Connector

Goal: prove local CAD workflows can be composed safely.

Minimum tools:

- `freecad.discover`;
- `freecad.open_document`;
- `freecad.create_document`;
- `freecad.apply_macro_proposal`;
- `freecad.validate_geometry`;
- `freecad.export_step`;
- `freecad.export_stl`;
- `freecad.export_preview`.

Required behavior:

- macros are proposal-first;
- exports include artifact type, geometry validation status, and receipt refs;
- unsafe file paths and external script imports fail closed.

Validation:

- fixture path when FreeCAD is unavailable;
- live smoke when FreeCAD exists locally;
- GUI workflow shows validation and export artifacts.

### Workstream 6: Read-Only Google Workspace And Mail

Goal: production data reads work through wallet-backed connector authority.

Minimum tools:

- `gmail.search`;
- `gmail.read_thread`;
- `drive.search_docs`;
- `drive.read_doc`;
- `calendar.find_availability`;
- `calendar.read_event`.

Required behavior:

- OAuth credentials live in wallet-backed vault;
- scopes are read-only by default;
- outputs pass through connector mappings and redaction policy where applicable;
- private content retention is explicit;
- no draft/send side effect is reachable from read-only grants.

Validation:

- credential readiness report;
- mocked connector contract tests;
- live read-only smoke when user credentials are present;
- no-secret/no-content-leak tests for logs and receipts.

### Workstream 7: Draft-Only Email, Calendar, And Doc Outputs

Goal: prepare external outputs safely without sending or publishing by default.

Minimum tools:

- `gmail.create_draft`;
- `calendar.create_event_draft`;
- `drive.create_doc_draft`;
- `drive.update_doc_draft`;
- `github.issue_draft` if GitHub is in scope.

Required behavior:

- drafts show preview artifacts;
- approval is required for external delivery;
- send/publish tools remain unavailable unless a separate grant and approval
  exist;
- draft outputs carry idempotency keys and provider response receipts.

Validation:

- draft creation smoke with mocked provider;
- live draft smoke when credentials exist;
- attempted send/publish without grant fails closed.

## Workflow Compositor Requirements

React Flow should expose Phase 5 as canonical primitives, not provider sprawl:

- `Tool Capability`;
- `Connector`;
- `Model Capability`;
- `Policy Gate`;
- `Approval`;
- `Repository`;
- `Browser / Computer`;
- `Sandboxed Computer`;
- `Artifact Output`;
- `Verification`.

Config, inspector tabs, and ports should carry provider-specific details:

- selected tool contract;
- credential readiness;
- authority scopes;
- approval requirement;
- dry-run/proposal mode;
- receipt behavior;
- artifact retention;
- redaction policy;
- retry/recovery policy.

## Autopilot Workbench Requirements

Every Phase 5 run should show:

- selected capability and contract version;
- credential readiness;
- authority grant and policy decision;
- proposal or dry-run preview;
- approval request and decision when applicable;
- executed adapter call;
- output schema validation;
- artifact refs;
- action and verification receipts;
- recovery guidance on failure.

The trace should be glass-box enough that a user can see the prompt move through
the workflow pipeline without confusing GUI state for runtime truth.

## Validation Net

Required final checks:

- static schema coverage for model/tool capability entries;
- no-secret leakage scans across logs, manifests, packages, receipts, and GUI
  state;
- contract tests for every Phase 5 tool;
- daemon/API/SDK/CLI/TUI projection tests;
- workflow manifest compatibility tests;
- GUI e2e for proposal, approval, execute, receipt, and fail-closed paths;
- browser/computer-use GUI trace probe that launches an approved target app
  through an isolated browser profile and records cleanup;
- Playwright adapter probe proving locator actionability, trace capture,
  artifact retention, and IOI receipt projection;
- profile-contamination guard proving the user's browser state is untouched;
- local shell/sandbox hardening tests;
- Blender/FreeCAD fixture tests and live smoke when available;
- Google Workspace/mail mocked tests and live smoke when credentials exist;
- readiness report shows external credential deferrals as narrow, explicit, and
  non-blocking for local-only lanes.

## Explicit Deferrals

Do not implement these in Phase 5:

- Instacart order submission;
- travel booking;
- invoice payment;
- funds transfer;
- irreversible commerce;
- unsupervised external publication;
- broad standing grants for external messaging;
- marketplace connector monetization.

Draft, preview, read-only, and local artifact-production paths may be built
earlier as long as they preserve authority, policy, and receipts.

## Definition Of Done

Phase 5 is complete when:

- filesystem/Git proposal-first mutation is production-grade;
- browser/computer-use hardening emits glass-box traces and receipts;
- local shell/sandbox hardening fails closed by default;
- Blender and FreeCAD/CAD have typed, receipted local artifact workflows;
- Google Workspace/mail read-only connectors are wallet-backed and redacted;
- email/calendar/doc outputs are draft-only unless explicitly approved;
- React Flow composes these capabilities through canonical primitives;
- Autopilot shows readiness, grants, policy, proposals, approvals, adapter
  calls, artifacts, and receipts;
- all targeted tests and GUI probes pass;
- high-risk commerce and irreversible external actions remain deferred;
- `git status` is clean except intentionally ignored generated evidence.

## First Tactical Slice After Entry Gate

Start with filesystem and Git proposal-first mutation:

1. finish contract entries;
2. expose read/diff/proposal/apply tools through the registry;
3. enforce preview plus policy before mutation;
4. project the tools into React Flow;
5. validate with CLI/TUI and Autopilot GUI receipts.

This lane is the best first proof because it exercises real production software
control while staying local, reversible, and highly inspectable.
