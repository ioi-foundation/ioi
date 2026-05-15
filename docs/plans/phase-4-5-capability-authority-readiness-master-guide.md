# Phase 4.5 Capability Authority Readiness Master Guide

Owner: daemon runtime / wallet.network / connectors-tools / model router / Autopilot / workflow compositor

Status: prerequisite leg, ready for implementation

Created: 2026-05-15

## Executive Verdict

Phase 5 should not begin until the live-action authority substrate is
production-shaped. The canonical roadmap already places connector/tool registry
and `wallet-core-lite` before early connector expansion. The implementation
roadmap still has stale sequencing that pushes some of this work later.

This guide defines the readiness leg that closes that drift:

> Before IOI expands into real production software, every live model, tool,
> connector, shell, browser, and workflow action must resolve through one
> capability registry, one wallet-backed authority path, one policy decision
> envelope, and one receipt-producing runtime event spine.

## Canonical Sources

- `docs/architecture/_meta/source-of-truth-map.md`
- `docs/roadmap.md`
- `docs/architecture/components/connectors-tools/doctrine.md`
- `docs/architecture/components/connectors-tools/contracts.md`
- `docs/architecture/components/wallet-network/doctrine.md`
- `docs/architecture/components/wallet-network/api-authority-scopes.md`
- `docs/architecture/components/model-router/doctrine.md`
- `docs/architecture/components/model-router/api-byok-mounting.md`
- `docs/architecture/foundations/security-privacy-policy-invariants.md`
- `docs/architecture/products/autopilot/internal-product-spec.md`
- `docs/plans/policy-platform-execution-master-guide.md`

If any supporting roadmap disagrees, the architecture files above win.

## Doctrine

- No second runtime.
- No React Flow shadow truth store.
- Daemon/runtime contracts own execution semantics.
- wallet.network owns secrets, grants, approvals, revocation, and audit
  lineage.
- Model providers, connector providers, browser/computer-use adapters, shell
  tools, and workflow tools are adapters into IOI contracts.
- Product UI configures and projects authority state. It does not become the
  authority source.
- Primitive execution capability and authority scope remain separate:
  `prim:*` describes runtime feasibility; `scope:*` describes wallet/provider
  authority.
- Every consequential action has a policy decision ref, authority grant ref
  when required, approval ref when required, idempotency story, and receipt
  behavior.

## Completion Dashboard

| Area                       | Current finding                                                                                                                                                                                                                                                                                                  | Target state                                                                                                                       | Status                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Roadmap alignment          | `docs/roadmap.md` gates Phase 5 correctly; implementation roadmap now routes through Phase 4.5 before Phase 5.                                                                                                                                                                                                   | One current sequencing story with stale docs marked or updated.                                                                    | Done / regression guarded                                                                          |
| Tool registry              | SDK, daemon `/v1/tools`, MCP serve descriptors, Rust service contracts, CLI inspection, TUI coding-tool rows, and React Flow/Autopilot workflow validation now expose or enforce readiness, approval, rate-limit, idempotency, receipt, availability, and marketplace fields.                                    | Daemon/API/SDK/CLI/TUI/Autopilot share one complete contract shape.                                                                | Partial / tool projection guarded; full Authority Center remains                                   |
| Model capability registry  | Daemon/API/SDK/CLI expose canonical model capability readiness contracts with privacy tier, provider priority, fallback policy, cost estimate visibility, vault/BYOK posture, receipt behavior, and workflow/agent availability; React Flow validation now blocks live model bindings that omit those contracts. | Workflow/model nodes call model capability routes with policy, BYOK, readiness, fallback, and receipt metadata.                    | Partial / registry and fail-closed projection guarded; Authority Center/workflow picker UX remains |
| wallet-core-lite           | Strong type/service pieces exist; Autopilot-facing encrypted vault and brokered action UX are incomplete.                                                                                                                                                                                                        | Secrets, BYOK, connector credentials, grants, approval tokens, revocation, audit, and step-up are user-visible and runtime-backed. | Open                                                                                               |
| Policy execution           | Scoped policy receipts exist in lanes, but cross-domain policy substrate is not yet the common control surface.                                                                                                                                                                                                  | One policy envelope governs connector, shell, computer-use, model, worker, memory, and artifact actions.                           | Open                                                                                               |
| Policy/Settings GUI        | Policy now opens as an Authority Center foundation with model/tool/connector capability readiness, grant, vault, blocker, and no-secret-leak projection; Settings labels raw env values as advanced compatibility rather than the primary authority path.                                                        | Authority Center with grants, vault refs, readiness, policy decisions, approvals, revocation, and receipt links.                   | Partial / foundation guarded; approval/revocation actions and receipt deep links remain            |
| Task-scoped GUI harness    | Recent live audit proved the desired method manually: choose the correct GUI lane, launch Autopilot, use an isolated browser profile, retain evidence outside git, and clean up the server.                                                                                                                      | Computer-use harness can perform the same method as a first-class runtime capability with receipts.                                | Open                                                                                               |
| Playwright adapter posture | Current browser stack is CDP/chromiumoxide/browser-use shaped; Playwright is not yet a first-class runtime provider.                                                                                                                                                                                             | Playwright is evaluated and mounted as a best-in-class browser automation adapter without becoming runtime truth.                  | Open                                                                                               |
| Workflow manifests         | Workflow nodes have useful `toolBinding`, `connectorBinding`, and model capability metadata fields, but provider-specific branches can still leak into authoring UX.                                                                                                                                             | Nodes bind to model/tool capabilities and compile to deterministic manifests with compatibility projections.                       | Partial / live model/tool contract validation guarded                                              |
| Validation                 | Tool and model registry contract slices now have targeted daemon/SDK/React Flow guards, but no single pre-Phase-5 go/no-go gate.                                                                                                                                                                                 | Static, runtime, GUI, and fail-closed tests prove safe live-action readiness.                                                      | Partial                                                                                            |

## Target End State

At completion, Phase 5 can safely begin because:

- every tool is represented by `RuntimeToolContract`;
- every model invocation uses a model route/capability contract;
- every connector credential and BYOK key is brokered through wallet-shaped
  authority, not raw product settings;
- every live side effect has risk class, policy target, approval posture,
  idempotency behavior, rate-limit posture, receipt behavior, and evidence
  requirements;
- Autopilot has a first-class Authority Center for grants, vault refs,
  readiness, approvals, revocation, and policy explanations;
- the computer-use harness can launch and inspect Autopilot itself through a
  task-scoped browser/app lease without contaminating the user's browser state;
- Playwright can be used where it is the best adapter for browser-context
  isolation, locator actionability, trace capture, and cross-browser validation,
  while IOI still owns actions, receipts, policy, and trajectories;
- React Flow workflow nodes bind to model/tool capabilities and authority
  scopes, not provider-specific shortcuts;
- invalid or under-authorized actions fail closed with recovery guidance.

## Contract Shape To Standardize

### Tool Capability

Every exposed tool capability should include:

- stable tool id and typed name;
- namespace and owner module;
- version;
- input schema and output schema;
- risk class and effect class;
- concurrency class and timeout policy;
- primitive capabilities required;
- authority scopes required;
- credential readiness;
- approval requirement and approval scope fields;
- rate-limit profile;
- idempotency behavior;
- receipt behavior and evidence requirements;
- redaction policy;
- workflow availability;
- agent availability;
- marketplace exposure eligibility;
- connector mapping and domain object refs when applicable.

### Model Capability

Every model route/capability should include:

- route id and model role;
- provider endpoint ref or local mount ref;
- privacy tier;
- supported modalities and tool-calling posture;
- context length and context strategy;
- cost estimate visibility;
- latency profile;
- fallback policy;
- BYOK/vault requirement;
- authority scope requirements;
- policy target;
- receipt behavior;
- readiness state and run-to-idle lifecycle state.

### Authority Grant

Every granted action should bind:

- subject;
- purpose;
- primitive capability constraints;
- authority scopes;
- resource constraints;
- expiry and max-call constraints;
- policy hash;
- request hash;
- revocation epoch;
- approval token when required;
- audit receipt ref.

### Task-Scoped GUI Harness Capability

The readiness gate must include the concrete behavior proved by the recent
manual audit session:

```text
classify_goal
-> choose GUI/browser lane
-> start target app or attach to approved target
-> create isolated browser profile / user data dir
-> open target URL or app surface
-> collect screenshots, logs, and observations outside git
-> inspect/click through the GUI
-> record action, observation, and cleanup receipts
-> stop target app and remove transient profile
```

The runtime contract should include:

- target app command or approved attach target;
- local URL or window target;
- isolated profile path or provider-managed user-data-dir;
- user-profile contamination policy;
- evidence output path and git-ignore posture;
- allowed tools and browser engine;
- cleanup behavior for server process, browser process, profile, and artifacts;
- `EnvironmentSelectionReceipt`, `ComputerUseLease`, `ObservationBundle`,
  `ActionReceipt`, `VerificationReceipt`, and `CleanupReceipt` refs.

This capability is not only for tests. It is the production-grade methodology
for inspecting Autopilot, local web apps, workflow composers, and policy
surfaces without borrowing the user's daily browser session.

Playwright should be a candidate implementation for this capability because it
already provides isolated browser contexts, resilient locators, actionability
checks, tracing, screenshots, video/log artifacts, and CDP access. It must still
compile into the same IOI contract spine:

```text
Playwright BrowserContext / Page / Locator / Trace
-> IOI ObservationBundle / TargetIndex / ActionProposal
-> IOI ComputerAction / ActionReceipt / VerificationReceipt
-> IOI TrajectoryBundle / CleanupReceipt
```

Forking Playwright should be treated as an escalation, not the default. Prefer a
thin `ioi.playwright_adapter` first; fork only for a documented blocker such as
missing deterministic trace hooks, required protocol instrumentation, or
unacceptable evidence/control limitations.

## Implementation Slices

### Slice 1: Roadmap Drift Removal

Goal: make sequencing unambiguous before implementation starts.

Work:

- update stale implementation roadmap sections that put model router/BYOK and
  wallet-core-lite after connector expansion;
- add a short pointer from Phase 5 planning back to this Phase 4.5 gate;
- keep canonical architecture files as the source of truth, not the plan docs.

Validation:

- static grep proves no current sequencing wording starts Phase 5 before the
  capability authority gate outside clearly historical context.

### Slice 2: Canonical Capability Registry Schema

Goal: one complete contract shape for native tools, MCP tools, connector tools,
workflow-as-tool subgraphs, and model capabilities.

Work:

- extend SDK catalog entries to include missing Phase 5 gate fields;
- align Rust service types, daemon JSON, SDK exports, CLI/TUI renderers, and
  Autopilot projections;
- expose complete readiness through `/v1/tools`, `/v1/connectors`, model
  capability APIs, and workflow validation;
- preserve compatibility adapters for old `capabilityScope`, `toolBinding`, and
  `connectorBinding` fields.

Validation:

- schema round-trip tests for native, MCP, connector, workflow-tool, and model
  route entries;
- fail closed when required contract fields are missing for live execution;
- CLI/TUI/SDK snapshots show the same risk, authority, readiness, and receipt
  fields.

### Slice 3: wallet-core-lite Product Slice

Goal: make wallet-shaped authority usable from Autopilot and enforceable by the
daemon.

Work:

- finish encrypted local secret store behavior;
- add model provider key vault and connector credential vault projections;
- create capability request and grant APIs for Autopilot;
- implement short-lived session grants, approval tokens, revocation, audit
  receipts, and step-up hooks;
- replace raw product secret values with `vault://` or wallet-network refs;
- guarantee no secret appears in logs, manifests, receipts, GUI exports, or
  generated evidence unless an explicit redacted/hash-only policy permits it.

Validation:

- no-leak tests for logs, events, GUI state, packages, and workflow manifests;
- revocation tests prove stale grants fail closed;
- BYOK and connector credential smoke tests use brokered refs, not raw values.

### Slice 4: Cross-Domain Policy Envelope

Goal: one policy substrate for model calls, tools, connectors, shell, computer
use, repository publishing, workers, memory, and artifacts.

Work:

- define the minimal `PolicyDecisionReceipt` envelope used across domains;
- bind policy decisions to action proposals before execution;
- ensure approval-required actions pause and resume through the same runtime
  event path;
- route missing, stale, or mismatched approval/grant refs to fail-closed
  blockers with recovery instructions.

Validation:

- connector, shell, computer-use, and model actions all emit comparable policy
  rows;
- policy replay reconstructs decisions from runtime events;
- stale approval and revoked grant tests fail closed.

### Slice 5: Task-Scoped GUI Harness Parity

Goal: turn the recent successful manual Autopilot GUI audit method into a
repeatable runtime capability.

Work:

- add a task-scoped browser/app lease shape for local GUI audits;
- support owned browser sessions with isolated profiles and no shared user
  browser state;
- add a Playwright adapter assessment and, if viable, a first-class
  `ioi.playwright` provider behind the same lease/action/receipt contracts;
- map Playwright locators, actionability failures, screenshots, console logs,
  network logs, and trace artifacts into IOI evidence refs;
- support target app lifecycle: start command, readiness probe, URL/window
  binding, shutdown, and cleanup;
- keep screenshots/logs/evidence outside git or under ignored evidence paths;
- emit environment-selection, observation, action, verification, and cleanup
  receipts;
- expose the capability through CLI/TUI and Autopilot readiness reporting.

Validation:

- launch Autopilot or a fixture GUI through the harness;
- prove the profile is isolated from the user's default browser profile;
- run at least one Playwright-backed smoke if the dependency/browser install is
  available, otherwise emit a narrow degraded-readiness result;
- capture screenshots and observations without committing generated evidence;
- click or inspect at least one target surface;
- shut down the target process and browser profile cleanly;
- fail closed when the browser engine, target app, readiness probe, or cleanup
  guarantee is unavailable.

### Slice 6: Autopilot Authority Center

Goal: replace the ancient Policy/Settings posture with a current operator-grade
authority workbench.

Work:

- promote Policy into an Authority Center surface;
- show grants, pending approvals, revocation, vault refs, connector/model
  readiness, policy decisions, budget/privacy posture, and receipt links;
- remove raw secret input as a primary settings pattern;
- replace freeform default model settings with model capability route readiness;
- preserve advanced/debug access to raw policy receipts and runtime ids;
- match the information density, interaction quality, and visual maturity of
  Workflow, Home, and Chat.

Validation:

- GUI e2e: open Policy, inspect authority grants, approve/deny a request,
  revoke a grant, and verify linked runtime receipt;
- GUI e2e: open Settings, add or inspect a vault-backed model/provider secret
  without exposing raw secret material;
- accessibility checks for tab order, labels, status text equivalents, and
  keyboard approval/revocation controls.

### Slice 7: Workflow Capability Binding

Goal: workflow authors choose capabilities and policy posture, while runtime
contracts remain authoritative.

Work:

- project canonical `Model Capability`, `Tool Capability`, and `Connector`
  bindings in React Flow;
- compile workflow manifests to model/tool capability refs and authority scopes;
- keep old stored workflows compatible through deterministic projection helpers;
- show readiness, required approvals, and receipt obligations in the inspector;
- prevent live runs when capability contract, credential readiness, grant, or
  policy decision is missing.

Validation:

- migration tests for old `toolBinding` and `connectorBinding`;
- manifest compatibility tests for existing workflows;
- GUI e2e: add capability node, inspect authority posture, run dry-run, and
  observe fail-closed/live behavior.

### Slice 8: Phase 5 Go/No-Go Gate

Goal: one command and one GUI path answer whether Phase 5 can begin.

Work:

- add a readiness report that checks registry, wallet, policy, settings,
  workflow, and daemon/API/SDK coverage;
- expose the same readiness in CLI/TUI and Autopilot;
- link failures to remediation sections.

Validation:

- clean environment report passes with local-only safe capabilities;
- degraded environment report marks missing providers without leaking secrets;
- live connector/model action attempts fail closed until the required readiness
  fields are present.

## Definition Of Ready For Phase 5

Phase 5 may begin only when:

- stale roadmap sequencing is resolved or explicitly marked historical;
- `RuntimeToolContract` and model capability contracts expose all readiness,
  policy, authority, idempotency, rate-limit, receipt, and availability fields;
- wallet-core-lite brokers BYOK keys and connector credentials through vault
  refs and authority grants;
- no Autopilot Settings path stores or displays raw long-lived secrets as the
  primary UX;
- task-scoped GUI harness runs can launch, inspect, capture evidence, and clean
  up local Autopilot or fixture app sessions without touching the user's browser
  profile;
- Policy/Settings provide a current Authority Center for grants, approvals,
  revocation, vault refs, policy decisions, readiness, and receipts;
- workflow activation and direct runtime calls fail closed without required
  contracts, grants, approvals, and receipt plans;
- CLI/TUI/SDK/daemon/Autopilot all project the same capability and authority
  facts;
- targeted tests and GUI validation pass;
- `git status` is clean except ignored generated evidence.

## Explicit Non-Goals

- Do not implement high-risk commerce connectors in this leg.
- Do not make wallet.network a workflow store, app database, or run trace
  database.
- Do not replace React Flow with a policy runtime.
- Do not expose provider-native secrets to make connector demos easier.
- Do not remove advanced/debug access to raw runtime ids and receipts.

## First Tactical Slice

Current immediate slice after the tool/model capability registry projections and
Authority Center foundation:

1. add Authority Center approval/revocation actions and receipt deep links;
2. start wallet-core-lite product slice once model/tool/connector projections
   agree on readiness, grants, approvals, and receipt fields.
3. wire workflow picker/inspector UX to model capability refs instead of
   provider-flavored shortcuts.

Historical first slice:

1. remove roadmap sequencing drift;
2. standardize the capability registry schema;
3. add fail-closed tests for missing live-action readiness fields.

That creates the frame for every later wallet, policy, settings, and workflow
change.
