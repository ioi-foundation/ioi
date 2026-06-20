# Hypervisor Reference-Grade Parity Master Guide

Status: implementation-grade recovery guide
Owner: Hypervisor App / Hypervisor Core implementation
Primary UX/product authority: `internal-docs/reverse-engineering/ioi`
Secondary architecture authority: `docs/architecture/`
Last reviewed: 2026-06-19

This guide is the concrete path from "shell-contract pass but functionally thin
browser client" to a reference-grade functional local Hypervisor demo. The goal
is not to clone the reference app verbatim. The goal is to capture the reference
app's functional density, route behavior, replay model, layout logic, and
interaction confidence, then translate that into the current Hypervisor canon:
Hypervisor is the operating environment for autonomous work; Hypervisor Core is
the shared runtime/control substrate executed by the Hypervisor Daemon;
wallet.network owns authority; Agentgres owns admitted operational truth;
storage holds bytes; App, Web, CLI/headless, and optional TUI are clients.

After these phases, the browser/dev Hypervisor App should stop feeling like an
illustrative prototype. It should be a functional local demo that starts,
hydrates, launches sessions, shows work history, opens project workbench state,
streams terminal/session projection, displays authority/model/privacy posture,
and records evidence without requiring authenticated third-party integrations.

## 1. Current Gap Diagnosis

The reference app feels more functional because it is a harvested production
mirror with a local replay backend. The current Hypervisor App is mostly a
browser client waiting for a daemon endpoint and a host bridge. The shell can
pass contract tests while the actual user experience remains thin.

### Evidence To Preserve

The following audit facts are part of the implementation baseline:

| Check                                                                                                          | Result                                                                                                                                                                                                | Meaning                                                                     |
| -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `npm run check:ioi-reference`                                                                                  | Passed with 0 console errors, 0 failed asset requests, and "100% parity."                                                                                                                             | The reference mirror has a working replay/verification story.               |
| `npm run build --workspace=@ioi/hypervisor-app`                                                                | Passed.                                                                                                                                                                                               | Hypervisor App compiles; this is not a build failure.                       |
| `node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/hypervisor-app-shell-contract-2026-06-19.json` | Passed.                                                                                                                                                                                               | Shell contract is green, but only after injecting a tiny contract daemon.   |
| Direct Playwright audit, shared routes                                                                         | Hypervisor: 0 service/backend requests. Reference: 273 service/backend requests.                                                                                                                      | Hypervisor browser mode is not exercising a real replay/backend surface.    |
| Reference replay                                                                                               | `/api`, `/segment`, supervisor calls, SSE streams, conversation history, editor URL resolution, hash-mapped payloads, and fallbacks are handled by `internal-docs/reverse-engineering/ioi/server.js`. | Reference functionality is source-backed, not screenshot-backed.            |
| Hypervisor daemon gating                                                                                       | Fetches are gated on `ioi.hypervisor.daemonEndpoint` in `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorDaemonEndpoint.ts`.                                                              | Browser/dev mode has no first-class local replay endpoint.                  |
| Hypervisor host bridge                                                                                         | Host actions throw without `window.__HYPERVISOR_HOST_BRIDGE__` in `apps/hypervisor/src/services/hypervisorHostBridge.ts`.                                                                             | Workbench and workspace flows break in plain Vite/browser mode.             |
| `/models`                                                                                                      | Tried `127.0.0.1:8765/v1/model-mount/snapshot` and got connection refused.                                                                                                                            | Model posture is wired to daemon routes, but the local dev route is absent. |
| `/authority`                                                                                                   | 15 failed runtime fetches.                                                                                                                                                                            | Authority center has contracts but no local replay contract server.         |
| `/workbench`                                                                                                   | Showed `No editor open`, host-bridge errors, and max-update-depth warnings.                                                                                                                           | Workbench has both missing data and a render-loop defect.                   |
| Agents, environments, foundry, privacy, workbench                                                              | Visibly fixture/degraded/offline.                                                                                                                                                                     | Static fixtures are filling space, not creating production-grade behavior.  |

### Diagnosis

1. The reference app is functional because its static mirror has a replay server
   that satisfies the product's expected route families. It serves static route
   HTML, API payloads, dynamic editor resolution, supervisor methods, conversation
   history, and SSE-like state.
2. Hypervisor App in plain browser mode has no equivalent local replay runtime.
   Its runtime fetches depend on a daemon endpoint key and many workspace actions
   depend on a host bridge object that does not exist in Vite/browser mode.
3. Shell-contract tests prove navigation, labels, and a few contract routes. They
   do not prove product functionality because the script injects a minimal daemon
   and does not hydrate every surface the way the reference replay server does.
4. Static fixtures and degraded cards can pass smoke tests while still feeling
   fake. A production-grade demo needs route-backed state, stream-like updates,
   terminal/session history, workbench artifacts, stable authority/model data,
   and evidence capture.
5. The request-volume mismatch is a symptom, not the target. Hypervisor should
   not chase exactly 273 requests, but every product route must exercise the same
   kind of route families as the reference app: app shell, API data, supervisor or
   daemon operations, live streams, history, editor/workspace resolution, assets,
   and graceful fallbacks.
6. Workbench is currently the sharpest failure because it needs workspace data,
   editor context, terminal projection, git status, problems, logs, ports, and
   host actions. Without replay-backed adapters, it collapses into "No editor
   open" and host bridge errors.

## 2. Source Authority And Capture Method

Implementation must be source-capture led. Screenshots are validation evidence,
not implementation source.

### Primary Reference Capture

Inspect these reference files and directories before implementing each slice:

| Reference source                                                      | What to capture                                                                                                                                               |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `internal-docs/reverse-engineering/ioi/server.js`                     | Local replay behavior, API fallbacks, SSE/history handling, supervisor method stubs, dynamic editor URL resolution, hash-based payload mapping, SPA fallback. |
| `internal-docs/reverse-engineering/ioi/verify.js`                     | Reference verification model: local server, console/resource audit, route walkthrough, failure classification.                                                |
| `internal-docs/reverse-engineering/ioi/public/index.html`             | Home shell, left navigation, New Session entry, workspace/session summary structure.                                                                          |
| `internal-docs/reverse-engineering/ioi/public/projects/index.html`    | Projects route layout, project list density, state hierarchy.                                                                                                 |
| `internal-docs/reverse-engineering/ioi/public/automations/index.html` | Automation list/composer structure, run history expectations, workflow density.                                                                               |
| `internal-docs/reverse-engineering/ioi/public/workspaces/index.html`  | Workspace/project detail behavior, changes panel, environment status, tasks, services, terminal/logs framing.                                                 |
| `internal-docs/reverse-engineering/ioi/public/insights/index.html`    | Monitoring/insights route density and operational summary patterns.                                                                                           |
| `internal-docs/reverse-engineering/ioi/public/ai/index.html`          | Session/chat/history flow and prompt surface behavior.                                                                                                        |
| `internal-docs/reverse-engineering/ioi/public/editor.html`            | Editor URL resolution target and embedded editor fallback behavior.                                                                                           |
| `internal-docs/reverse-engineering/ioi/public/api/**`                 | Captured payload contracts and request families.                                                                                                              |
| `internal-docs/reverse-engineering/ioi/public/logs/**`                | Log payload shape and terminal/log inspector expectations.                                                                                                    |
| `internal-docs/reverse-engineering/ioi/scratch/history_*.json`        | Conversation history chunk shape and live-session hydration.                                                                                                  |
| `internal-docs/reverse-engineering/ioi/temp_details/*.html`           | Session detail tabs and execution detail structure.                                                                                                           |
| `internal-docs/reverse-engineering/ioi/docs/mirror_blueprint.md`      | Mirror design notes and source-capture context.                                                                                                               |
| `internal-docs/reverse-engineering/ioi/tools/capture_screenshots.js`  | Screenshot capture workflow for parity evidence only.                                                                                                         |
| `internal-docs/reverse-engineering/ioi/tools/traffic/*.js`            | Route/request logging ideas for parity audits.                                                                                                                |

### Hypervisor Capture

Inspect these Hypervisor files before implementing each slice:

| Hypervisor source                                                                             | What to capture                                                                                            |
| --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `apps/hypervisor/README.md`                                                                   | Client/daemon authority boundary.                                                                          |
| `apps/hypervisor/src/main.tsx`                                                                | Browser boot path and route mounting.                                                                      |
| `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorShellNavigationModel.ts`         | Current shell IA, reference nav list, pinned/primary surface model.                                        |
| `apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx`     | Left shell rendering.                                                                                      |
| `apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorLeftSidebarShell.tsx` | Sidebar/workspace profile structure.                                                                       |
| `apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx`  | New Session flow and harness/model selection.                                                              |
| `apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorShellContent.tsx`     | Surface routing and fallback rendering.                                                                    |
| `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorDaemonEndpoint.ts`               | Daemon endpoint storage and fetch gate.                                                                    |
| `apps/hypervisor/src/services/hypervisorHostBridge.ts`                                        | Host bridge availability and error behavior.                                                               |
| `apps/hypervisor/src/services/workspaceAdapter.ts`                                            | Workbench/workspace host actions.                                                                          |
| `apps/hypervisor/src/windows/HypervisorShellWindow/*Model.ts`                                 | Current route contracts for projects, sessions, automations, providers, privacy, receipts, agents, models. |
| `apps/hypervisor/src/surfaces/**`                                                             | Surface-specific UX and degraded states.                                                                   |
| `packages/runtime-daemon/src/http/public-runtime-routes.mjs`                                  | Daemon public routes and existing model/authority/session contracts.                                       |
| `packages/runtime-daemon/src/model-mounting/**`                                               | Local model mount and OpenAI-compatible/Ollama route support.                                              |
| `packages/runtime-daemon/src/harness-shims/**`                                                | Existing Claude Code/generic CLI adapter fixtures.                                                         |
| `packages/runtime-daemon/src/runtime-harness-session-*.mjs`                                   | Recipe, binding, launch, spawn, readiness, terminal attach admission flow.                                 |
| `scripts/hypervisor-app-shell-contract.mjs`                                                   | Existing shell contract and injected tiny daemon routes.                                                   |

### Capture Rules

1. Read source, routes, CSS/layout classes, payload fixtures, server handlers, and
   route logs before changing UI.
2. Convert reference product structure into Hypervisor language. Do not copy
   labels that contradict canon.
3. Use screenshots only after source capture to confirm visual/behavioral parity.
4. Record every audit as JSON under `.tmp/` during local iteration. Promote only
   curated evidence to `docs/evidence/` when it supports an architectural claim.
5. Keep screenshots attached to route/source notes. A screenshot without the
   source route and payload that produced it is not implementation evidence.

## 3. Target UX Architecture

The target product shape is a Hypervisor operating shell, not an IDE shell.

### Shell IA

The left shell must converge on this structure:

```text
+ New Session

Home
Projects
Automations
Applications
Sessions

Pinned Applications
  Foundry
  Models
  Workers
  Connectors
  Policies
  Receipts
  Monitoring

Organization / Workspace
User profile
```

Required cuts:

1. No legacy Build/Run/Govern/Verify console as the parent product.
2. No old IDE-only framing.
3. No Tauri resurrection.
4. No root `ide/` resurrection.
5. No bridge product surface.
6. No separate Fleet app posture.
7. No Workbench-as-parent-product layout.

### Surface Roles

| Surface                | Canon role                                                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Home                   | Default command and resumption surface: start work, inspect active work, resume sessions, view recommended actions.                                |
| Projects               | Durable software/system work containers. A project can open Workbench mode, sessions, automations, receipts, files, and environment posture.       |
| Automations            | Durable workflows, pipelines, APIs, and agentic services. Canvas is a visual builder inside this surface.                                          |
| Applications           | Catalog and launcher for specialized Hypervisor surfaces: Foundry, Models, Workers, Connectors, Policies, Receipts, Monitoring, and vertical apps. |
| Sessions               | Live and historical governed execution contexts across chat, projects, automations, applications, workers, models, tools, compute, and editors.    |
| Workbench              | Project editing/inspection mode. It is opened from Projects/Sessions, not treated as the parent product.                                           |
| Foundry                | Application for agent/model/worker training, eval, packaging, hardening, and publishing.                                                           |
| Models                 | Application for model mounts, capabilities, routing, privacy posture, and local provider status.                                                   |
| Authority/Policies     | Application surface projecting wallet.network authority decisions, approvals, secrets, leases, declassification, spend, and revocation.            |
| Receipts/Replay        | Application surface projecting Agentgres-admitted receipts, state roots, artifact refs, archive/restore validity, and replay truth.                |
| Environments/Providers | Provider and infrastructure posture inside Hypervisor sessions/projects/provider/environment views, not a separate Fleet product.                  |

### Functional Demo Definition

The local browser/dev demo is reference-grade when:

1. Every top-level route hydrates from a local replay/dev harness or real daemon.
2. Missing daemon endpoint falls into dev replay mode in development, not broken
   screens.
3. Host actions in browser/dev mode are serviced by typed replay routes or return
   controlled unavailable states, not uncontrolled thrown UX errors.
4. Sessions can be created, inspected, streamed, resumed, and replayed with local
   Qwen-backed harness adapters before authenticated third-party integrations.
5. Workbench opens a default project/workspace session with file tree, editor,
   source-control state, terminal projection, problems, ports, logs, and receipts.
6. Models, authority, privacy, environments, foundry, and receipts show stable
   route-backed state.
7. The app records route calls, console errors, failed assets, bad responses, and
   screenshots into reproducible evidence JSON.

## 4. Reference-Grade Local Replay / Dev Harness

This is the highest-priority implementation. Hypervisor needs a local replay/dev
harness similar in spirit to `internal-docs/reverse-engineering/ioi/server.js`,
but aligned to Hypervisor contracts.

### New Harness Artifacts

Add these files unless a better existing home emerges during implementation:

| File                                                                                      | Purpose                                                                                                                                                                    |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/hypervisor-app-dev-replay-server.mjs`                                            | Local replay server that implements daemon-compatible dev routes, host-bridge replay routes, SSE/session streams, evidence collection, and SPA/static serving when needed. |
| `scripts/hypervisor-reference-parity-audit.mjs`                                           | Playwright side-by-side audit runner for reference vs Hypervisor route coverage, console errors, failed assets, bad responses, screenshots, and interaction probes.        |
| `apps/hypervisor/src/dev/hypervisorDevReplayClient.ts`                                    | Browser-only helper for discovering/seeding the dev replay endpoint in development.                                                                                        |
| `apps/hypervisor/src/dev/hypervisorDevHostBridge.ts`                                      | Development host bridge shim that maps host actions to replay routes without becoming product surface.                                                                     |
| `apps/hypervisor/src/dev/replayContracts.ts`                                              | Shared TypeScript contracts for replay route payloads.                                                                                                                     |
| `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorReplayEvidenceModel.ts`      | Optional model for showing evidence/replay state in Receipts/Replay, not in the shell chrome.                                                                              |
| `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorApplicationsCatalogModel.ts` | Applications catalog model once the Applications shell becomes first class.                                                                                                |
| `packages/runtime-daemon/src/http/public-runtime-routes.mjs`                              | Add or align real daemon routes that the dev replay server mirrors.                                                                                                        |
| `packages/runtime-daemon/src/http/public-runtime-routes.test.mjs`                         | Contract tests for every route mirrored by dev replay.                                                                                                                     |
| `apps/hypervisor/src/**/*.test.*`                                                         | Surface tests for no degraded default state when replay routes are available.                                                                                              |

### Endpoint Seeding

In development:

1. Start `scripts/hypervisor-app-dev-replay-server.mjs` on `127.0.0.1:8765` by
   default, or print the selected port if occupied.
2. Seed `ioi.hypervisor.daemonEndpoint` to the replay endpoint automatically in
   Vite/browser dev mode only.
3. Do not seed in production builds unless an explicit test harness does it.
4. The seeding path must be visible and testable:

```text
apps/hypervisor/src/dev/hypervisorDevReplayClient.ts
  -> detects import.meta.env.DEV
  -> probes http://127.0.0.1:8765/v1/hypervisor/dev-replay/status
  -> writes localStorage["ioi.hypervisor.daemonEndpoint"]
  -> emits a typed replay capability flag to shell models
```

The shell-contract script already injects the endpoint manually. This guide
requires the app's dev path to do that predictably when the local replay harness
is running.

### Replay Route Families

The dev replay server must expose daemon-shaped route families. Route names may
be refined during implementation, but every family below must exist.

| Family                 | Routes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Health/capabilities    | `GET /v1/hypervisor/dev-replay/status`, `GET /v1/hypervisor/capabilities`, `GET /v1/tools`                                                                                                                                                                                                                                                                                                                                                                                                   |
| Home                   | `GET /v1/hypervisor/home-cockpit`, `GET /v1/hypervisor/recommended-actions`                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Projects               | `GET /v1/hypervisor/projects`, `GET /v1/hypervisor/projects/:project_id`, `GET /v1/hypervisor/projects/:project_id/state`, `GET /v1/hypervisor/projects/:project_id/activity`                                                                                                                                                                                                                                                                                                                |
| Automations            | `GET /v1/hypervisor/automations`, `GET /v1/hypervisor/automations/:automation_id`, `GET /v1/hypervisor/automation-runs`, `POST /v1/hypervisor/automation-runs/proposals`                                                                                                                                                                                                                                                                                                                     |
| Applications           | `GET /v1/hypervisor/applications`, `GET /v1/hypervisor/applications/:application_id`, `POST /v1/hypervisor/applications/:application_id/pin`                                                                                                                                                                                                                                                                                                                                                 |
| Sessions               | `GET /v1/hypervisor/sessions`, `POST /v1/hypervisor/sessions`, `GET /v1/hypervisor/sessions/:session_id`, `GET /v1/hypervisor/sessions/:session_id/events`, `GET /v1/hypervisor/sessions/:session_id/history`                                                                                                                                                                                                                                                                                |
| Session launch         | `POST /v1/hypervisor/session-launch-recipe-admissions`, `POST /v1/hypervisor/harness-session-binding-admissions`, `POST /v1/hypervisor/harness-session-launches`, `POST /v1/hypervisor/harness-session-spawns`, `POST /v1/hypervisor/harness-session-readiness`, `POST /v1/hypervisor/harness-session-terminal-attachments`                                                                                                                                                                  |
| Workbench              | `GET /v1/hypervisor/workbench/snapshot`, `GET /v1/hypervisor/workbench/files`, `GET /v1/hypervisor/workbench/file`, `GET /v1/hypervisor/workbench/git/status`, `GET /v1/hypervisor/workbench/git/diff`, `GET /v1/hypervisor/workbench/problems`, `GET /v1/hypervisor/workbench/ports`, `GET /v1/hypervisor/workbench/logs`, `POST /v1/hypervisor/workbench/terminal`, `GET /v1/hypervisor/workbench/terminal/:terminal_id/read`, `POST /v1/hypervisor/workbench/terminal/:terminal_id/write` |
| Models                 | `GET /v1/model-mount/snapshot`, `GET /v1/model-capabilities`, `GET /v1/hypervisor/model-routes`, `POST /v1/hypervisor/model-routes/proposals`                                                                                                                                                                                                                                                                                                                                                |
| Authority              | `GET /v1/model-mount/authority`, `GET /v1/authority-evidence`, `GET /v1/hypervisor/policies`, `GET /v1/hypervisor/approvals`, `POST /v1/hypervisor/approvals/proposals`                                                                                                                                                                                                                                                                                                                      |
| Agents/workers         | `GET /v1/hypervisor/agents`, `GET /v1/hypervisor/workers`, `GET /v1/hypervisor/harness-adapters`, `POST /v1/hypervisor/harness-adapters/proposals`                                                                                                                                                                                                                                                                                                                                           |
| Environments/providers | `GET /v1/hypervisor/environments`, `GET /v1/hypervisor/provider-placement`, `GET /v1/hypervisor/compute-posture`                                                                                                                                                                                                                                                                                                                                                                             |
| Foundry                | `GET /v1/hypervisor/foundry/jobs`, `GET /v1/hypervisor/foundry/evals`, `GET /v1/hypervisor/foundry/packages`, `POST /v1/hypervisor/foundry/jobs/proposals`                                                                                                                                                                                                                                                                                                                                   |
| Privacy                | `GET /v1/hypervisor/privacy-posture`, `GET /v1/hypervisor/declassification-requests`, `POST /v1/hypervisor/declassification-requests/proposals`                                                                                                                                                                                                                                                                                                                                              |
| Receipts/replay        | `GET /v1/hypervisor/receipts`, `GET /v1/hypervisor/receipts/:receipt_id`, `GET /v1/hypervisor/replay/:replay_id`, `GET /v1/hypervisor/artifact-refs`, `GET /v1/hypervisor/archive-restore-validity`                                                                                                                                                                                                                                                                                          |
| Evidence               | `GET /v1/hypervisor/dev-replay/evidence`, `POST /v1/hypervisor/dev-replay/evidence/reset`                                                                                                                                                                                                                                                                                                                                                                                                    |

### Replay Data Rules

1. Payloads must be deterministic and typed.
2. Payloads must look like daemon/Core projections, not arbitrary UI fixtures.
3. Every consequential operation is a proposal or daemon-admitted contract event.
4. Replay data can simulate admissions and projections, but the response shape
   must match the real daemon route shape or a route slated to be added to the
   daemon.
5. SSE/stream-like behavior is required for sessions and terminal projection:

```text
GET /v1/hypervisor/sessions/:session_id/events
  Content-Type: text/event-stream
  event: session_state
  event: terminal_chunk
  event: receipt_projection
  event: readiness
```

6. Evidence collection must include route, method, status, payload family,
   request hash where useful, response family, timing, console errors, failed
   assets, bad responses, screenshot paths, and route-family coverage.
7. The replay server must not become a new runtime. Its README/header must say:
   "development replay scaffold over Hypervisor Daemon/Core contracts; not an
   authority source."

## 5. Host Bridge And Daemon Boundary

Browser/dev behavior must be controlled, not broken.

### Correct Behavior

| Situation                                               | Required behavior                                                                                           |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Daemon endpoint exists and responds                     | Use the daemon endpoint.                                                                                    |
| Daemon endpoint missing in development                  | Probe local dev replay; seed `ioi.hypervisor.daemonEndpoint`; show route-backed replay state.               |
| Daemon endpoint missing outside development             | Show a controlled setup state with the exact missing requirement and no thrown UI error.                    |
| Host bridge exists                                      | Use `window.__HYPERVISOR_HOST_BRIDGE__` for local host actions.                                             |
| Host bridge missing in development with replay endpoint | Install dev host bridge shim backed by replay routes.                                                       |
| Host bridge missing outside development                 | Return typed unavailable results and user-actionable setup state. Do not throw uncontrolled surface errors. |

### Implementation Boundary

1. `apps/hypervisor/src/services/hypervisorHostBridge.ts` should expose a typed
   `getHypervisorHostBridgeOrReplay()` style path, not raw throwing behavior from
   user-facing surfaces.
2. `apps/hypervisor/src/services/workspaceAdapter.ts` should treat bridge calls
   as adapters with structured errors. A missing bridge should not bubble as a
   React console error in normal dev replay mode.
3. All consequential execution remains daemon/Core routed:
   - recipe admission
   - harness binding admission
   - launch
   - spawn
   - readiness
   - terminal attach
   - transcript projection
   - receipts/replay refs
4. Replay/dev harness is development scaffolding only. It can simulate daemon
   projections, but it cannot become runtime truth, wallet authority, Agentgres
   truth, or storage authority.

## 6. Sessions Engine Plan

The first functional session engines should avoid authenticated third-party
provider dependencies. Start with local/Qwen routes and harness adapters, then
add authed integrations after the local loop is dependable.

### First Engines

| Engine                     | Adapter role          | Initial model path                              | Notes                                                        |
| -------------------------- | --------------------- | ----------------------------------------------- | ------------------------------------------------------------ |
| Codex OSS / Qwen           | Agent Harness Adapter | Local OpenAI-compatible or Ollama Qwen route    | Treat as proposal source; daemon admits recipe and launch.   |
| DeepSeek TUI / Qwen        | Agent Harness Adapter | Local OpenAI-compatible or Ollama Qwen route    | Terminal-first adapter with transcript projection.           |
| Claude Code example / Qwen | Agent Harness Adapter | Existing example shim plus local Qwen route     | Example harness only until authed Claude integration exists. |
| Generic CLI / Qwen         | Agent Harness Adapter | Existing generic CLI shim plus local Qwen route | Baseline for arbitrary local tools.                          |

### Existing Implementation Anchors

| Source                                                                                       | Use                                                                      |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `packages/runtime-daemon/src/model-mounting/**`                                              | Local model mount, OpenAI-compatible/Ollama routing, model capabilities. |
| `packages/runtime-daemon/src/runtime-hypervisor-session-launch-recipe-admission.mjs`         | Admission of session launch recipe.                                      |
| `packages/runtime-daemon/src/runtime-harness-session-binding-admission.mjs`                  | Admission of adapter binding.                                            |
| `packages/runtime-daemon/src/runtime-harness-session-launch.mjs`                             | Launch contract.                                                         |
| `packages/runtime-daemon/src/runtime-harness-session-spawn.mjs`                              | Spawn contract.                                                          |
| `packages/runtime-daemon/src/runtime-harness-session-readiness.mjs`                          | Readiness contract.                                                      |
| `packages/runtime-daemon/src/runtime-harness-session-terminal-attach.mjs`                    | Terminal attach contract.                                                |
| `packages/runtime-daemon/src/harness-shims/claude-code-example.mjs`                          | Example Claude Code adapter shape.                                       |
| `packages/runtime-daemon/src/harness-shims/generic-cli-local.mjs`                            | Generic CLI local adapter shape.                                         |
| `apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts`                   | App-side harness selection/admission model.                              |
| `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorSessionOperationsModel.ts`      | App-side session launch/readiness/terminal flow.                         |
| `apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorNewSessionModal.tsx` | User-facing launch flow.                                                 |

### Required Session Flow

Every adapter must project the same high-level flow:

```text
New Session
  -> select project/context
  -> select harness adapter
  -> select local Qwen model route
  -> propose launch recipe
  -> daemon admits recipe
  -> daemon admits harness binding
  -> daemon launches session
  -> daemon spawns harness
  -> readiness event
  -> terminal attach
  -> transcript projection
  -> receipt/replay refs
```

The adapter is a proposal and execution harness. It is not a Hypervisor client,
not runtime truth, and not an authority source.

## 7. Workbench Recovery

Workbench must become a functional project mode, not a dead editor placeholder.

### Required Fixes

1. Remove `No editor open` as the default state. Default route must mount a
   project/workspace session with a selected file, terminal, git status, logs,
   ports, and problems.
2. Fix max update depth warnings before any parity claim. Add a focused test that
   mounts Workbench under replay state and fails on repeated render recursion.
3. Replace uncontrolled host-bridge errors with replay-backed workspace adapter
   results in development.
4. Provide these replay-backed panels:

| Workbench panel | Route source                                                                                                                                                     |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File tree       | `GET /v1/hypervisor/workbench/files`                                                                                                                             |
| Editor          | `GET /v1/hypervisor/workbench/file?path=...`                                                                                                                     |
| Source control  | `GET /v1/hypervisor/workbench/git/status`, `GET /v1/hypervisor/workbench/git/diff`                                                                               |
| Terminal        | `POST /v1/hypervisor/workbench/terminal`, `GET /v1/hypervisor/workbench/terminal/:terminal_id/read`, `POST /v1/hypervisor/workbench/terminal/:terminal_id/write` |
| Problems        | `GET /v1/hypervisor/workbench/problems`                                                                                                                          |
| Ports/services  | `GET /v1/hypervisor/workbench/ports`                                                                                                                             |
| Logs            | `GET /v1/hypervisor/workbench/logs`                                                                                                                              |
| Receipts        | `GET /v1/hypervisor/receipts?project_id=...`                                                                                                                     |
| Session link    | `GET /v1/hypervisor/sessions/:session_id`                                                                                                                        |

5. Editor adapter choices belong in project/session preferences:
   `codeEditorAdapterPreferences.ts` remains a preference model, not a bridge
   product surface.
6. Workbench should be reachable from Projects and Sessions. It can keep a direct
   dev route for testing, but the product framing is "project mode."

## 8. Surface-By-Surface Parity Matrix

Each row is a real implementation slice. A surface is not complete because it has
cards. It is complete when its route-backed states, interactions, and evidence
match the acceptance criteria.

| Surface         | Reference source files to inspect                                                                                                     | Current Hypervisor files                                                                                                                                                                                     | Missing backend/replay routes                                                                                                                                                        | Missing UX states                                                                                                  | Implementation slice                                                                                                                     | Acceptance criteria                                                                                                             | Playwright evidence required                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Home            | `public/index.html`, `server.js`, `public/api/**`, `scratch/root_dom.html`, `tools/capture_screenshots.js`                            | `surfaces/Home/HomeView.tsx`, `surfaces/Home/homeCockpitModel.ts`, `HypervisorShellContent.tsx`, `operatorSubstrateModel.ts`                                                                                 | `GET /v1/hypervisor/home-cockpit`, `GET /v1/hypervisor/recommended-actions`, `GET /v1/hypervisor/sessions`, `GET /v1/hypervisor/projects`                                            | Real active work, recent sessions, project resumption, recommended action queue, local replay status               | Replace static/degraded summaries with replay-backed cockpit model; add New Session and resume links wired to sessions/projects          | Home loads with route-backed active session/project/action data; no degraded default in dev replay; New Session and resume work | Home screenshot, request log with home/session/project families, 0 console errors, 0 failed assets           |
| Projects        | `public/projects/index.html`, `public/workspaces/index.html`, `server.js`, `public/api/gitpod.v1.WorkspaceService/**`                 | `hypervisorProjectStateModel.ts`, `HomeView.tsx`, `WorkspaceShell.tsx`, `HypervisorShellContent.tsx`                                                                                                         | `GET /v1/hypervisor/projects`, `GET /v1/hypervisor/projects/:id`, `GET /v1/hypervisor/projects/:id/state`, `GET /v1/hypervisor/projects/:id/activity`                                | Durable project objects, project health, repo/workspace links, active sessions, open Workbench action              | Build Projects surface as durable container list/detail; wire Workbench open from project row/detail                                     | Projects route shows multiple real project states, opens Workbench with selected project, links sessions/receipts               | Projects screenshot, project detail/workbench transition trace, request log                                  |
| Automations     | `public/automations/index.html`, `server.js`, `public/api/gitpod.v1.WorkflowService/**`                                               | `surfaces/Automations/AutomationsWorkflowComposerView.tsx`, `hypervisorAutomationCompositorModel.ts`                                                                                                         | `GET /v1/hypervisor/automations`, `GET /v1/hypervisor/automations/:id`, `GET /v1/hypervisor/automation-runs`, `POST /v1/hypervisor/automation-runs/proposals`                        | Run history, graph node contracts, trigger states, proposal/admission status, canvas-inside-Automations            | Convert composer into route-backed automation catalog plus builder mode; keep Canvas inside Automations                                  | Automations route displays workflows, run history, node status, and proposal flow without fake static-only state                | Automations screenshot, automation run route evidence, proposal response evidence                            |
| Applications    | Product spec attachment, `public/index.html` shell patterns, `public/insights/index.html`, settings/catalog-like patterns             | `hypervisorShellNavigationModel.ts`, `HypervisorActivityRail.tsx`, `HypervisorLeftSidebarShell.tsx`, `HypervisorShellContent.tsx`                                                                            | `GET /v1/hypervisor/applications`, `GET /v1/hypervisor/applications/:id`, `POST /v1/hypervisor/applications/:id/pin`                                                                 | Catalog, categories, pinned applications, app details, launch/open state                                           | Add Applications as top-level shell route; move Foundry/Models/Workers/Connectors/Policies/Receipts/Monitoring under catalog/pinned apps | Left nav is Home/Projects/Automations/Applications/Sessions; pinned apps below; Applications opens route-backed catalog         | Shell screenshot, nav order assertion, catalog route log, pin/unpin interaction evidence                     |
| Sessions        | `public/ai/index.html`, `temp_details/*.html`, `scratch/history_*.json`, `server.js` SSE/history handlers                             | `hypervisorSessionOperationsModel.ts`, `hypervisorLaunchedSessionPersistence.ts`, `HypervisorNewSessionModal.tsx`, `harnessAdapterModel.ts`                                                                  | `GET/POST /v1/hypervisor/sessions`, `GET /v1/hypervisor/sessions/:id`, `GET /v1/hypervisor/sessions/:id/events`, `GET /v1/hypervisor/sessions/:id/history`, launch/admission routes  | Live session stream, historical session detail, terminal transcript, readiness state, receipt refs                 | Implement Sessions list/detail/stream using local Qwen harness adapters and replay SSE                                                   | New local session can be launched, appears in Sessions, streams readiness/terminal chunks, persists history                     | New Session video/screenshot sequence, SSE request evidence, session detail screenshot, receipt ref evidence |
| Workbench       | `public/workspaces/index.html`, `public/editor.html`, `public/logs/**`, `server.js` supervisor methods and ResolveEditorURL           | `surfaces/Workspace/WorkspaceShell.tsx`, `services/workspaceAdapter.ts`, `hypervisorHostBridge.ts`, `codeEditorAdapterPreferences.ts`, `useHypervisorShellController.ts`                                     | `GET /v1/hypervisor/workbench/snapshot`, files, file, git/status, git/diff, terminal read/write, problems, ports, logs                                                               | Default project mount, file tree, selected editor, source control, terminal, problems, ports, logs, no render loop | Add dev host bridge shim and route-backed workspace adapter; remove default dead state                                                   | Workbench opens with selected project/file, terminal/log/git panels hydrate, no max update depth warning, no bridge error       | Workbench screenshot, console audit, terminal interaction trace, render-loop guard output                    |
| Models          | Reference model/provider status patterns in `public/index.html`, `public/insights/index.html`; route behavior in `server.js`          | `surfaces/Models/ModelMountsSurfaceView.tsx`, `modelMountInventoryModel.ts`, `hypervisorModelInfrastructureModel.ts`, `packages/runtime-daemon/src/model-mounting/**`                                        | `GET /v1/model-mount/snapshot`, `GET /v1/model-capabilities`, `GET /v1/hypervisor/model-routes`, `POST /v1/hypervisor/model-routes/proposals`                                        | Local Qwen route health, OpenAI-compatible/Ollama status, capabilities, privacy posture, proposal state            | Make local replay server satisfy model routes; wire Models to stable route-backed state in dev                                           | `/models` has no connection refused; local Qwen mount appears; capabilities and routing are stable                              | Models screenshot, request log, no failed 127.0.0.1 connection evidence                                      |
| Authority       | Settings/secrets/token/integration patterns in reference `public/**`, `server.js` route fallbacks                                     | `surfaces/Policy/AuthorityCenterPanel.tsx`, `surfaces/Policy/authorityCenterRuntime.ts`, `surfaces/Authority/AuthoritySettingsSurfaceView.tsx`, `packages/runtime-daemon/src/http/public-runtime-routes.mjs` | `GET /v1/model-mount/authority`, `GET /v1/authority-evidence`, `GET /v1/hypervisor/policies`, `GET /v1/hypervisor/approvals`, approval proposal routes                               | Wallet-owned approval states, leases, secrets, revocations, spend/declassification gates, evidence chain           | Replay authority projections using wallet.network language; keep Core non-authoritative                                                  | `/authority` has 0 failed runtime fetches; shows approval/evidence states; proposal path returns daemon-shaped response         | Authority screenshot, 0 failed fetch audit, authority route evidence                                         |
| Agents          | Reference session/execution patterns in `public/ai/index.html`, `temp_details/*.html`, `scratch/history_*.json`                       | `hypervisorAgentsModel.ts`, `harnessAdapterModel.ts`, `HypervisorNewSessionModal.tsx`                                                                                                                        | `GET /v1/hypervisor/agents`, `GET /v1/hypervisor/harness-adapters`, harness proposal/admission routes                                                                                | Agent/harness distinction, adapter readiness, local engine availability, execution history                         | Reframe agents as adapter/harness-backed proposal sources and workers, not clients                                                       | Agents route is not degraded; adapters show Codex OSS/Qwen, DeepSeek TUI/Qwen, Claude example/Qwen, generic CLI/Qwen            | Agents screenshot, adapter list route evidence, launch proposal evidence                                     |
| Environments    | `public/workspaces/index.html`, `public/insights/index.html`, `/vm-live-usage/` handler in `server.js`                                | `surfaces/Environments/EnvironmentEstateView.tsx`, `hypervisorProviderPlacementModel.ts`, `hypervisorModelInfrastructureModel.ts`                                                                            | `GET /v1/hypervisor/environments`, `GET /v1/hypervisor/provider-placement`, `GET /v1/hypervisor/compute-posture`                                                                     | Local/dev environment health, project environment binding, VM/resource usage, provider placement                   | Move provider posture inside environment/project/session views; remove Fleet-product drift                                               | Environments route shows route-backed estate, local runtime health, provider placement, no degraded default                     | Environments screenshot, resource/provider route log                                                         |
| Foundry         | Reference catalog/settings/session patterns, `public/automations/index.html`, `temp_details/*.html`                                   | `HypervisorShellContent.tsx`, Foundry branch/model code in shell files, `harnessAdapterModel.ts`                                                                                                             | `GET /v1/hypervisor/foundry/jobs`, `GET /v1/hypervisor/foundry/evals`, `GET /v1/hypervisor/foundry/packages`, proposal routes                                                        | Eval jobs, training/tuning hooks, packaging/publishing, benchmark results, worker/agent relation                   | Build Foundry as Applications item with route-backed job/eval/package state                                                              | Foundry route is not fixture-only; jobs/evals/packages display stable data and proposal affordances                             | Foundry screenshot, job/eval/package request evidence                                                        |
| Privacy         | Reference settings/security patterns, route fallback behavior in `server.js`                                                          | `hypervisorPrivacyPostureModel.ts`, `AuthorityCenterPanel.tsx`, policy surfaces                                                                                                                              | `GET /v1/hypervisor/privacy-posture`, `GET /v1/hypervisor/declassification-requests`, proposal routes                                                                                | cTEE/local/provider privacy states, declassification requests, wallet gates, receipt links                         | Route-backed privacy posture that differentiates local/private from provider trust                                                       | Privacy route is not degraded; declassification proposal and evidence links render                                              | Privacy screenshot, privacy/declassification route evidence                                                  |
| Receipts/Replay | Reference session details/logs/history: `temp_details/*.html`, `public/logs/**`, `scratch/history_*.json`, SSE/history in `server.js` | `hypervisorReceiptEvidenceModel.ts`, receipt surfaces in shell/content, `packages/runtime-daemon/src/runtime-lifecycle-projection-api*`                                                                      | `GET /v1/hypervisor/receipts`, `GET /v1/hypervisor/receipts/:id`, `GET /v1/hypervisor/replay/:id`, `GET /v1/hypervisor/artifact-refs`, `GET /v1/hypervisor/archive-restore-validity` | Receipt detail, replay timeline, artifact refs, state roots, archive/restore validity                              | Make Receipts/Replay the visible Agentgres projection surface for demo sessions/projects                                                 | Receipts list/detail/replay is route-backed; session/workbench link to receipt refs; no static-only state                       | Receipts screenshot, replay timeline interaction, route/evidence JSON                                        |

## 9. Implementation Phases

The phases below are hard slices. Do not merge a phase because screenshots look
plausible. Merge when the tests and evidence prove the contracts are live.

### Phase 0: Source Capture And Parity Matrix

| Field                | Detail                                                                                                                                                                                         |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Convert the reference mirror into a source-captured parity backlog and lock the architecture translation.                                                                                      |
| Files likely touched | `internal-docs/implementation/hypervisor-reference-grade-parity-master-guide.md`, optional `.tmp/hypervisor-reference-capture-*.json`.                                                         |
| Work                 | Inspect `server.js`, `verify.js`, route HTML, payload directories, history JSON, logs, current Hypervisor shell/source, and canon docs. Fill route-family matrix and current failure evidence. |
| Tests/commands       | `npm run check:ioi-reference`; `git diff --check`.                                                                                                                                             |
| Evidence             | `.tmp/hypervisor-vs-reference-playwright-functional-audit.json`, `.tmp/hypervisor-extra-routes-audit.json`, screenshots only as validation.                                                    |
| Risks                | Treating screenshots as source; copying reference labels that conflict with Hypervisor canon.                                                                                                  |
| Commit boundary      | Stand-alone docs-only capture guide.                                                                                                                                                           |

### Phase 1: Local Replay/Dev Harness And Daemon Endpoint Seeding

| Field                | Detail                                                                                                                                                                                                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Goal                 | Give browser/dev Hypervisor a local daemon-shaped replay endpoint and automatic endpoint discovery.                                                                                                                                                                                                          |
| Files likely touched | `scripts/hypervisor-app-dev-replay-server.mjs`, `apps/hypervisor/src/dev/hypervisorDevReplayClient.ts`, `apps/hypervisor/src/windows/HypervisorShellWindow/hypervisorDaemonEndpoint.ts`, `scripts/hypervisor-app-shell-contract.mjs`, package scripts.                                                       |
| Work                 | Implement replay server health/capability routes, seed `ioi.hypervisor.daemonEndpoint` in dev, record evidence, and keep production behavior explicit.                                                                                                                                                       |
| Tests/commands       | `node scripts/hypervisor-app-dev-replay-server.mjs --port 8765 --evidence .tmp/hypervisor-app-dev-replay-server.json`; `npm run build --workspace=@ioi/hypervisor-app`; `node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/hypervisor-app-shell-contract-$(date +%F).json`; `git diff --check`. |
| Evidence             | Dev endpoint status, seeded localStorage proof, route log, no connection refused for replay health/model snapshot.                                                                                                                                                                                           |
| Risks                | Accidentally creating a second runtime; seeding endpoint outside dev/test.                                                                                                                                                                                                                                   |
| Commit boundary      | Harness starts, endpoint seeds, shell contract still passes.                                                                                                                                                                                                                                                 |

### Phase 2: Route Stubs/Replay For Broken Surfaces

| Field                | Detail                                                                                                                                                                                                                                                                                                                       |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Replace degraded/offline defaults with typed replay-backed route state across broken surfaces.                                                                                                                                                                                                                               |
| Files likely touched | `scripts/hypervisor-app-dev-replay-server.mjs`, `apps/hypervisor/src/windows/HypervisorShellWindow/*Model.ts`, `apps/hypervisor/src/surfaces/Models/ModelMountsSurfaceView.tsx`, `apps/hypervisor/src/surfaces/Policy/authorityCenterRuntime.ts`, `packages/runtime-daemon/src/http/public-runtime-routes.mjs`, route tests. |
| Work                 | Add replay routes for Models, Authority, Agents, Environments, Foundry, Privacy, Receipts, Home, Projects, Automations, Applications, Sessions. Normalize client fetch models to daemon-shaped payloads.                                                                                                                     |
| Tests/commands       | Focused model tests; `npm run build --workspace=@ioi/hypervisor-app`; `node scripts/hypervisor-reference-parity-audit.mjs --hypervisor http://127.0.0.1:1420 --evidence .tmp/hypervisor-reference-parity-audit-phase2.json`; `git diff --check`.                                                                             |
| Evidence             | 0 failed runtime fetches on `/models` and `/authority`; no degraded default on Agents/Environments/Foundry/Privacy.                                                                                                                                                                                                          |
| Risks                | Static fixtures masquerading as replay; route names drifting away from daemon route names.                                                                                                                                                                                                                                   |
| Commit boundary      | Every currently broken surface hydrates from replay route families.                                                                                                                                                                                                                                                          |

### Phase 3: Workbench Functional Parity

| Field                | Detail                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Turn Workbench from dead editor state into functional project inspection/edit mode.                                                                                                                                                                                                                                                                 |
| Files likely touched | `apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx`, `apps/hypervisor/src/services/workspaceAdapter.ts`, `apps/hypervisor/src/services/hypervisorHostBridge.ts`, `apps/hypervisor/src/dev/hypervisorDevHostBridge.ts`, `apps/hypervisor/src/windows/HypervisorShellWindow/useHypervisorShellController.ts`, Workbench tests, replay server. |
| Work                 | Add dev host bridge shim, workbench snapshot/files/git/terminal/problems/ports/logs routes, default project mount, selected file state, terminal projection, render-loop fix.                                                                                                                                                                       |
| Tests/commands       | Focused Workbench React/unit test for no max-update-depth; Playwright `/workbench` audit; `npm run build --workspace=@ioi/hypervisor-app`; `git diff --check`.                                                                                                                                                                                      |
| Evidence             | `/workbench` screenshot with file tree/editor/terminal/git/logs; console errors 0; no host bridge missing error; terminal read/write route evidence.                                                                                                                                                                                                |
| Risks                | Letting Workbench become parent product again; burying bridge failures in hidden compatibility shims.                                                                                                                                                                                                                                               |
| Commit boundary      | Workbench opens from Project and direct dev route without broken default state.                                                                                                                                                                                                                                                                     |

### Phase 4: Sessions And Harness Adapters With Local Qwen Model Mount

| Field                | Detail                                                                                                                                                                                                                                                                                                                           |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Make New Session create real local demo sessions through daemon-shaped adapter contracts.                                                                                                                                                                                                                                        |
| Files likely touched | `packages/runtime-daemon/src/model-mounting/**`, `packages/runtime-daemon/src/harness-shims/**`, `packages/runtime-daemon/src/runtime-harness-session-*.mjs`, `apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts`, `hypervisorSessionOperationsModel.ts`, `HypervisorNewSessionModal.tsx`, replay server. |
| Work                 | Wire Codex OSS/Qwen, DeepSeek TUI/Qwen, Claude Code example/Qwen, and generic CLI/Qwen as Agent Harness Adapters. Add route-backed New Session flow with admission, launch, spawn, readiness, terminal attach, transcript projection, receipts.                                                                                  |
| Tests/commands       | Runtime daemon harness tests; model mounting tests; Playwright New Session flow; `npm run build --workspace=@ioi/hypervisor-app`; `git diff --check`.                                                                                                                                                                            |
| Evidence             | New Session creates a local session; Sessions list/detail updates; SSE stream emits readiness/terminal chunks; receipt/replay refs show.                                                                                                                                                                                         |
| Risks                | Treating external harnesses as clients; adding authed third-party integrations before local loop works.                                                                                                                                                                                                                          |
| Commit boundary      | At least one local Qwen-backed harness session works end to end in replay/dev mode.                                                                                                                                                                                                                                              |

### Phase 5: Projects/Home/Applications IA Parity

| Field                | Detail                                                                                                                                                                                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Align the shell with the clean Hypervisor product IA.                                                                                                                                                                         |
| Files likely touched | `hypervisorShellNavigationModel.ts`, `HypervisorActivityRail.tsx`, `HypervisorLeftSidebarShell.tsx`, `HypervisorShellContent.tsx`, `HomeView.tsx`, project/application models and tests.                                      |
| Work                 | Change top-level shell to Home, Projects, Automations, Applications, Sessions. Move Foundry/Models/Workers/Connectors/Policies/Receipts/Monitoring under pinned Applications. Add organization/workspace profile bottom area. |
| Tests/commands       | Navigation model tests; shell contract update; Playwright shell/nav audit; `npm run build --workspace=@ioi/hypervisor-app`; `git diff --check`.                                                                               |
| Evidence             | Shell screenshot, nav-order assertion, Applications catalog screenshot, pinned app interaction evidence.                                                                                                                      |
| Risks                | Keeping too many legacy top-level tabs; preserving old Build/Run/Govern/Verify mental model.                                                                                                                                  |
| Commit boundary      | IA is visibly and testably clean.                                                                                                                                                                                             |

### Phase 6: Automations/Foundry/Receipts Replay Parity

| Field                | Detail                                                                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Give durable workflows, agent production, and replay truth the same functional density as sessions/workbench.                                                                         |
| Files likely touched | `AutomationsWorkflowComposerView.tsx`, `hypervisorAutomationCompositorModel.ts`, Foundry surface/model files, `hypervisorReceiptEvidenceModel.ts`, replay server, daemon route tests. |
| Work                 | Add route-backed automation graph/run history/proposals, Foundry jobs/evals/packages/proposals, receipt detail/replay timeline/artifact refs/archive validity.                        |
| Tests/commands       | Surface tests; Playwright route probes; `npm run build --workspace=@ioi/hypervisor-app`; `git diff --check`.                                                                          |
| Evidence             | Automation run proposal, Foundry eval/job detail, receipt replay timeline, artifact refs.                                                                                             |
| Risks                | Foundry becoming a miscellaneous tab; receipts becoming decorative instead of Agentgres projection.                                                                                   |
| Commit boundary      | Automations, Foundry, and Receipts are route-backed and interactive in dev replay mode.                                                                                               |

### Phase 7: Playwright Parity Gate And Cleanup

| Field                | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Goal                 | Make reference-grade parity a repeatable gate, not a one-off manual audit.                                                                                                                                                                                                                                                                                                                                                                            |
| Files likely touched | `scripts/hypervisor-reference-parity-audit.mjs`, `scripts/hypervisor-app-shell-contract.mjs`, package scripts, docs/evidence index if promoted.                                                                                                                                                                                                                                                                                                       |
| Work                 | Side-by-side route coverage, console/resource audit, visual screenshots, interaction probes, evidence JSON writing, cleanup of hidden shims and stale fixtures.                                                                                                                                                                                                                                                                                       |
| Tests/commands       | `npm run check:ioi-reference`; `npm run build --workspace=@ioi/hypervisor-app`; `node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/hypervisor-app-shell-contract-$(date +%F).json`; `node scripts/hypervisor-reference-parity-audit.mjs --reference http://127.0.0.1:9226 --hypervisor http://127.0.0.1:1420 --evidence .tmp/hypervisor-reference-parity-audit-final.json`; `git diff --check`; architecture doc checks if docs changed. |
| Evidence             | Final JSON with route-family coverage, screenshots, console/resource audit, workbench render-loop proof, model/authority/session route stability.                                                                                                                                                                                                                                                                                                     |
| Risks                | Optimizing for screenshots; leaving compatibility shims; route count games instead of route-family completeness.                                                                                                                                                                                                                                                                                                                                      |
| Commit boundary      | Demo parity gate is repeatable and green.                                                                                                                                                                                                                                                                                                                                                                                                             |

## 10. Anti-Patterns / Hard Cuts

These are rejected implementation paths:

1. Screenshots as implementation source. Screenshots validate, source implements.
2. Static fixture-only UX passing as parity.
3. Shell-contract tests treated as sufficient proof.
4. A new runtime beside the Hypervisor Daemon.
5. Hypervisor Core replacing wallet.network authority.
6. Hypervisor Core replacing Agentgres truth.
7. Storage backends becoming truth sources.
8. Tauri resurrection.
9. Root `ide/` resurrection.
10. Legacy Build/Run/Govern/Verify console as the product parent.
11. Workbench as the parent product.
12. Canvas as the product plane instead of a builder inside Automations.
13. Fleet as a separate app.
14. External harnesses such as Codex, Claude Code, DeepSeek TUI, or generic CLI
    treated as Hypervisor clients or runtime truth.
15. Provider-trust fallback pretending to be private/local model route.
16. Hidden compatibility shims that keep old behavior alive.
17. Monolithic or unintuitive files that bury product contracts in giant UI
    components.
18. Authed third-party provider integrations before local Qwen-backed session
    engines work.

## 11. Verification Gates

Reference-grade parity requires all gates below.

### Required Commands

```bash
npm run check:ioi-reference
npm run build --workspace=@ioi/hypervisor-app
node scripts/hypervisor-app-shell-contract.mjs --evidence .tmp/hypervisor-app-shell-contract-$(date +%F).json
node scripts/hypervisor-reference-parity-audit.mjs --reference http://127.0.0.1:9226 --hypervisor http://127.0.0.1:1420 --evidence .tmp/hypervisor-reference-parity-audit-final.json
git diff --check
```

If architecture docs are touched, run the repository's architecture-doc check:

```bash
npm run check:architecture-docs
```

If the package script name changes during implementation, update this guide in
the same commit that introduces the new command.

### Gate Criteria

| Gate                                   | Required result                                                                                                                                                                                         |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reference verifier                     | `npm run check:ioi-reference` passes with 0 console errors and 0 failed assets.                                                                                                                         |
| Hypervisor build                       | `npm run build --workspace=@ioi/hypervisor-app` passes.                                                                                                                                                 |
| Shell contract                         | Shell contract passes, but is treated as baseline only.                                                                                                                                                 |
| Side-by-side Playwright route coverage | Reference and Hypervisor shared route families are comparable: app shell, API/data, supervisor/daemon operations, streams/history, editor/workspace resolution, assets, fallbacks.                      |
| Console errors                         | 0 user-facing console errors in Hypervisor dev replay mode.                                                                                                                                             |
| Failed assets                          | 0 failed asset requests.                                                                                                                                                                                |
| Missing daemon/host bridge             | 0 missing daemon endpoint or missing host bridge errors in dev replay mode.                                                                                                                             |
| Model routes                           | `/v1/model-mount/snapshot`, `/v1/model-capabilities`, and model route proposals return stable data.                                                                                                     |
| Authority routes                       | `/v1/model-mount/authority`, `/v1/authority-evidence`, policies, approvals, and proposal routes return stable data.                                                                                     |
| Session routes                         | Session list/detail/history/events and launch/admission routes return stable data and stream-like events.                                                                                               |
| Workbench                              | No infinite render loop; no `No editor open` default; files/git/terminal/problems/ports/logs hydrate.                                                                                                   |
| Route count                            | Do not chase exact 273 requests, but Hypervisor must no longer show 0 service/backend requests on shared routes. Route-family coverage must be complete and request volume must reflect real hydration. |
| Evidence                               | Final JSON written to `.tmp/` during iteration; curated evidence promoted to `docs/evidence/` only when appropriate.                                                                                    |
| Diff hygiene                           | `git diff --check` passes.                                                                                                                                                                              |
| Architecture docs                      | Architecture checks pass if canon docs are touched.                                                                                                                                                     |

### Final Evidence JSON Shape

The final parity audit should write a JSON object with this minimum shape:

```json
{
  "generated_at": "2026-06-19T00:00:00.000Z",
  "reference": {
    "base_url": "http://127.0.0.1:9226",
    "routes": [],
    "console_errors": 0,
    "failed_assets": 0,
    "route_families": []
  },
  "hypervisor": {
    "base_url": "http://127.0.0.1:1420",
    "routes": [],
    "console_errors": 0,
    "failed_assets": 0,
    "bad_responses": [],
    "route_families": [],
    "screenshots": [],
    "workbench": {
      "render_loop_warnings": 0,
      "host_bridge_errors": 0,
      "default_editor_open": true
    },
    "models": {
      "snapshot_ok": true
    },
    "authority": {
      "evidence_ok": true
    },
    "sessions": {
      "events_stream_ok": true,
      "terminal_projection_ok": true
    }
  }
}
```

## 12. Output And Integration

This guide is stand-alone on purpose. Do not split its implementation plan across
`internal-docs/implementation/refine-architecture.md` while the Hypervisor App UX
recovery is active. That avoids a split-brain plan where one doc says "fix the
shell" and another doc owns the actual route, replay, session, and Workbench
work.

If any part of this plan graduates into stable canon, move only the architecture
ownership delta into `docs/architecture/`. Keep replay harness mechanics, audit
commands, phase evidence, and demo-specific implementation details here unless
they become stable product contracts.

### Implementation-Ready Checklist

Use this checklist before claiming the parity recovery is done:

```text
[ ] Reference source capture complete.
[ ] Hypervisor current source capture complete.
[ ] Local dev replay server starts.
[ ] Dev endpoint seeding works.
[ ] Host bridge missing state degrades into replay/dev contract mode.
[ ] Models route has no connection refused.
[ ] Authority route has no failed runtime fetches.
[ ] Workbench opens a default project/workspace session.
[ ] Workbench has no max update depth warning.
[ ] Sessions launch through local Qwen-backed Agent Harness Adapter.
[ ] Terminal transcript projection appears in Sessions and Workbench.
[ ] Receipts/replay refs appear for sessions and projects.
[ ] Shell IA is Home, Projects, Automations, Applications, Sessions.
[ ] Pinned Applications include Foundry, Models, Workers, Connectors, Policies, Receipts, Monitoring.
[ ] No legacy Build/Run/Govern/Verify console remains as parent surface.
[ ] No hidden compatibility shims remain.
[ ] Playwright side-by-side parity gate passes.
[ ] Build passes.
[ ] git diff --check passes.
```

The finish line is a functional local Hypervisor product demo: route-backed,
stream-capable, session-capable, workbench-capable, authority/model/privacy
aware, and evidence-producing. Anything less is still shell polish.
