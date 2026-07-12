# Hypervisor Daemon and IOI CLI Runtime Specification

Status: canonical architecture authority.
Canonical owner: this file for Hypervisor Daemon, CLI ownership boundaries, and IOI CLI operator-surface positioning; low-level daemon endpoints live in [`api.md`](./api.md).
Supersedes: older CLI/daemon wording that implies the CLI owns runtime semantics or is primarily a chain/domain generator.
Superseded by: none.
Last alignment pass: 2026-07-11.
Doctrine status: canonical
Implementation status: partial (the daemon is the single runtime surface; hosted/DePIN endpoint families planned)
Implementation refs:
  - `crates/node/src/bin/hypervisor-daemon.rs`
Last implementation audit: 2026-07-05

## Canonical Definition

**The Hypervisor Daemon is the universal execution endpoint and
hypervisor/control plane for canonical Web4 autonomous work.**

The daemon is a hypervisor by analogy: it does not make workers, models, tools,
connectors, browsers, shells, or computer-use providers trustworthy by existing.
It supervises them as guest workloads/capabilities under scoped authority,
policy, receipts, replay, and settlement hooks. Clients and operator surfaces
may request, display, approve, interrupt, or inspect work, but the daemon owns
execution semantics. Agentgres owns admitted durable run truth.

**`ioi-cli` is the canonical local/operator interface to IOI runtimes,
domains, manifests, receipts, authority scopes, and mainnet/application-domain
interactions.**

The IOI CLI is a terminal/TUI client over daemon/public runtime APIs and
the broader canonical Web4 stack, with headless mode for scripting. It may
mirror daemon commands, render operator workflows, resolve natural-language
intent into inspectable plans, and administer domain/settlement/authority
surfaces. A TUI may be offered as an interactive presentation of the CLI, but
it is not a separate first-class runtime or client lane.
The CLI must not own a separate agent runtime or execution loop.

Through daemon APIs, it launches workflows, agents, workers, tools, models,
connectors, worker-training jobs, benchmark jobs, evaluation jobs, MoW routing
decisions, and artifact-producing jobs across local, hosted, provider, DePIN,
TEE, and enterprise environments.

Hypervisor Core is the shared product/runtime substrate over this daemon-owned
execution boundary. Hypervisor App, Hypervisor Web, CLI/headless, SDK, ADK,
benchmarks, and extension hosts are first-class clients, builder frameworks, or
projections; they do not become private runtimes. A TUI is an optional
presentation of CLI/headless controls. The Hypervisor application
suite (Studio, Automations, Ontology, Data, Governance, Missions, Provenance, Evaluations, Improvement, Foundry, Marketplace, Workbench, Developer Console), the Environments and Operations substrate lane,
generated domain apps, Privacy / cTEE, Change Plane views, and Patterns /
Examples / Training facets are projections over the same Core, not separate
runtime truth paths. Agent Studio is Studio's agent lens; ODK is the
developer kit beneath Ontology and Data; the former Work Ledger views
converge in Provenance.

Hypervisor Workbench is the live code/systems surface. VS Code, Cursor,
Windsurf, JetBrains, browser IDEs, terminals, VMs, local OS surfaces, and
HypervisorOS nodes are adapter targets for Hypervisor Sessions, not
Hypervisor's product identity. External CLI or hosted agent harnesses such as
Codex, Claude Code, Grok Build, OpenHands, Aider, shell/tmux agents, CI agents,
and hosted coding agents are Agent Harness Adapters, not Hypervisor clients or
runtime truth.

HypervisorOS is the bare-metal node profile for this same daemon substrate. It
does not create a peer runtime. It makes the Hypervisor Daemon the node root for
serious local, provider, marketplace, enterprise, or DePIN nodes so autonomous
workloads run under daemon policy, measurement, receipts, and capability exits.

The CLI/headless client, optional TUI presentation, SDK, and ADK are distinct:

```text
CLI/headless = operator, scripting, CI, and node-ops client
TUI          = optional interactive presentation of CLI/headless controls
SDK          = low-level protocol/client library
ADK          = autonomous-system builder framework
```

The SDK may submit, inspect, stream, and control work through daemon/domain
contracts. The ADK may scaffold workers, service modules, harnesses, evals,
manifests, receipts, and deployment profiles on top of SDK and daemon/domain
contracts. Neither replaces the daemon/runtime substrate.

IOI Authority Gateway is the compatibility sidecar/profile for existing IDEs,
CLI agents, hosted-agent tools, browser automation, MCP ecosystems, shell
wrappers, Git hooks, API proxies, credential brokers, and CI/CD gates. It exists
to let users keep their IDE and keep their model while putting consequential
execution behind IOI. It is a daemon deployment/adoption profile, not a second
runtime and not a replacement for Hypervisor App, Hypervisor Web, CLI/headless,
or the Hypervisor Workbench surface as first-party operator experiences.

> **Models reason. Hypervisor Daemon gates action. IOI settles what needs public
> trust.**

Adapters may observe, request, preview, deny, transform, or submit proposed
actions through the daemon. They must not claim total interception over opaque
third-party runtimes. Their job is to mediate the control points they can
actually see: shell commands, file mutations, Git operations, MCP/tool calls,
secret leases, browser actions, deploy/API calls, webhooks, and CI/CD gates.

Compute-node rule:

> **Runtime and compute nodes initialize Hypervisor Daemon runtime-node profiles. The
> SDK is a client over that substrate, not the substrate booted on the node.**

Harness profile rule:

> **HarnessProfiles are daemon-executed or daemon-mediated step-resolution
> contracts. The Default Harness Profile is IOI's reference scaffold/fallback,
> not a peer runtime, not the only admissible harness, and not a meta-harness.**

The implementation-grade profile contract lives in
[`default-harness-profile.md`](./default-harness-profile.md). It defines the
HarnessProfile boundary, Default Harness Profile reference behavior,
loop-native lifecycle, context topology, action proposal and gate path,
Agentgres admission rules, artifact/ref boundary, output ownership pass, and
conformance phases used by selected harness profiles.

Agent operating plane rule:

> **Agents are configurable product objects; agent execution is daemon-owned.**

The daemon owns configured agent records, agent/session admission, work queues,
work items, work runs, thread/turn controls, conversation streams, subagent
delegation, runner reconciliation, model/LLM usage reporting, exec/security
telemetry, receipts, and Agentgres bindings. Product controls such as Agent,
Mode, Model, Reasoning, Speed, and Harness compile into daemon contracts rather
than creating client-local loops.

## Hypervisor Node Boundary

A Hypervisor Node is the local autonomous-system settlement and interop domain
composed around Hypervisor Core clients/surfaces, the Hypervisor Daemon,
Agentgres, wallet.network authority paths, local registries, receipt/replay
stores, and runtime profiles.

The daemon is the execution and authority-enforcement substrate inside that
node. Hypervisor App, Hypervisor Web, CLI/headless, optional TUI views, and
application surfaces such as Workbench, Foundry, and Environments
views are operator clients/projections. Agentgres is the local operational
truth substrate. AIIP is
the semantic interop protocol for local microharness routing and external
autonomous-system handoffs.
Authority providers and local/domain governance authorize as required.
wallet.network supplies portable delegated authority for secrets, provider
credentials, external effects, spend, decryption, declassification,
restore/apply, high-risk approvals, and other portable or consequential power.
IOI L1 receives selected roots when public
trust, economic settlement, reputation portability, dispute resolution, or
cross-system handoff finality requires them.

The daemon may execute an autonomous-system harness as a modular
state-transition pipeline. Consequential harness steps are typed
service-module invocations: they read state, apply policy, invoke workers,
tools, models, or connectors, emit receipts, and propose or commit bounded
state transitions through Agentgres-compatible operations.

The Hypervisor Daemon owns model routing and invocation boundaries, not implicit model
possession. Model weights, local model files, model servers, BYOK provider
access, hosted pools, TEE sessions, DePIN sessions, and customer VPC endpoints
are deployment-profile resources. Bundled model weights are allowed only when a
node/runtime profile explicitly declares them.

Do not describe Hypervisor clients or application surfaces as the settlement layer. Do not
describe the daemon as IOI L1. Local Hypervisor Node settlement means local
canonical acceptance of work, state transitions, proposals, receipts, authority
outcomes, and AIIP interop messages; IOI L1 settlement means public registry,
rights, dispute, reputation, handoff finality, and economic finality.

## CLI Operator Surface

The CLI should feel like the structured operator shell for the whole IOI/Web4
stack, not primarily like a chain/domain generator.

One-line positioning:

> **`ioi-cli` resolves operator intent into inspectable plans, invokes IOI
> daemon runtimes, manages Agentgres domains, binds wallet.network authority
> scopes, publishes `ai://` manifests, verifies receipts, and interacts with
> IOI L1 settlement contracts.**

The CLI can be natural-language capable, but structured plans, canonical
commands, manifests, receipts, and replayable execution remain durable truth.

The optional TUI is the interactive presentation of the same operator client. It
may provide rich thread, turn, approval, memory, MCP, subagent, snapshot,
restore, diagnostics, usage, and context-budget controls, but every control
must resolve to daemon/public runtime APIs or domain-kernel APIs. It must not
carry a private execution loop or become a separate first-class client lane.

### Core Command Families

```text
ioi runtime
  local/hosted/depin/tee node operations

ioi agent
  product-facing agent aliases for worker install/run/status/inspect

ioi worker
  install/run/status/inspect/publish

ioi service
  sas.xyz service order/delivery/acceptance/dispute

ioi domain
  Agentgres domain init/status/migrate/export/import

ioi agentgres
  query/project/receipt/projection/admin

ioi wallet
  authority scope request/grant/revoke/approve

ioi ai
  ai:// resolve/register/publish/verify

ioi l1
  contract calls, escrow, license, dispute, bond, settlement

ioi artifact
  inspect/verify/materialize/fetch/publish

ioi receipt
  inspect/verify/export/bundle

ioi model
  mount/list/route/benchmark

ioi train
  spec/create/run/evaluate/benchmark/publish

ioi data
  ontology/recipe/mapping/view/dataset/projection inspect/run/verify

ioi mow
  route/candidates/decision/inspect/receipt

ioi connector
  bind/list/test/revoke

ioi forge
  advanced domain/kernel scaffolding only
```

`forge` remains an advanced namespace for domain/kernel scaffolding. It is not
the primary identity of the CLI.

When CLI prose says "Web4 L0," it refers to the IOI kernel/L0 substrate:
domain scaffolding, manifests, policy roots, receipts, runtime profiles, and
upgrade objects. The CLI is an operator client over that substrate. It is not
the L0 substrate itself, and it is not the execution runtime.

### Intent Resolution Contract

Natural-language CLI input must resolve into:

```text
operator intent
→ candidate plan
→ explicit execution path
→ preview/dry-run when mutation is possible
→ canonical command/envelope
→ authority/policy decision
→ daemon/domain/L1 action
→ receipts, trace, and replay/export
```

The CLI should surface local/BYOK/managed/TEE/DePIN routing, model/key/provider
availability, privacy, cost, latency, and authority implications before it
crosses trust boundaries.

### Hypervisor Bridge

Hypervisor may emit typed artifacts, manifests, receipts, evidence plans, and
CLI-compatible workflow/domain packages. The CLI may inspect, validate,
materialize, promote, publish, route, or verify them through daemon and
Agentgres APIs. The CLI does not become the Hypervisor runtime.

Hypervisor App, Hypervisor Web, CLI/headless, Workbench/Foundry surfaces, other
application surfaces, and Environments views
may manage or inspect local Hypervisor Daemons and render local runtime
projections. Remote, hosted, provider, DePIN, TEE, and customer runtime nodes
should still be described as Hypervisor Daemon runtime-node profiles, even when
they run Hypervisor-compatible workflow packages.

### Authority Gateway / Sidecar Profile

The Authority Gateway profile is the adoption wedge for users who already live
inside Cursor, VS Code, JetBrains, Codex, Claude Code, Grok Build,
OpenHands-like tools, Aider, shell/tmux agents, CI agents, or hosted agent
products. The product message is:

> **Keep your IDE. Keep your model. Put consequential execution behind IOI.**

The sidecar routes proposed actions into the same daemon policy, authority,
approval, receipt, replay, and settlement path used by first-party Hypervisor
clients and application surfaces.
Different tools expose different control points. VS Code-family tools can use
extensions, terminals, workspace watchers, and MCP gateways. CLI agents can run
as guest workloads behind shell wrappers and tool proxies. Hosted agent systems
may require API gateways, GitHub Apps, CI/CD policy gates, webhook mediation, or
receipt ingestion.

This profile strengthens the marketplace/protocol thesis instead of competing
with it: developers can first govern existing models and agents, then discover
better workers, install marketplace workers, delegate authority through
wallet.network, and graduate to Hypervisor App, Hypervisor Web, or Workbench
when they need the native control room.

## Runtime Role

The daemon executes work. It does not own root authority or global marketplace state.

It is responsible for:

- starting runs;
- pausing/resuming/canceling runs;
- executing workflow nodes;
- executing typed service-module invocations;
- invoking model router;
- calling tools/connectors;
- producing artifacts;
- emitting events and receipts;
- enforcing policy/firewall gates;
- requesting wallet authority scopes;
- syncing outputs to Agentgres;
- fetching packages from selected storage backends through Agentgres-governed refs;
- streaming status to apps.

## Deployment Targets

1. **Local Hypervisor Daemon under Hypervisor App or Workbench** — desktop/private execution.
2. **Hosted Hypervisor Daemon** — always-on hosted workers/services.
3. **Provider daemon** — service provider infrastructure.
4. **DePIN daemon** — Akash-like public compute.
5. **HypervisorOS daemon** — bare-metal node image where the daemon is the root
   control plane for autonomous workloads.
6. **TEE-verified daemon** — enterprise secure mode.
7. **Customer VPC daemon** — enterprise private runtime.
8. **IOI Authority Gateway sidecar** — local/private or controlled-cloud
   mediation profile for existing IDEs, CLI agents, hosted agents, MCP tools,
   shell/Git surfaces, browser actions, API gateways, and CI/CD gates.

## Public Runtime API

Minimum API surface:

```http
GET  /v1/runtime/manifest
GET  /v1/runtime/health
POST /v1/workers/install
GET  /v1/workers/{id}
POST /v1/runs
GET  /v1/runs/{id}
GET  /v1/runs/{id}/events
GET  /v1/runs/{id}/artifacts
GET  /v1/runs/{id}/receipts
POST /v1/runs/{id}/pause
POST /v1/runs/{id}/resume
POST /v1/runs/{id}/cancel
GET  /v1/deliveries/{id}
```

Interactive clients and builder frameworks such as Hypervisor App/Web,
CLI/headless, optional TUI views, SDK, ADK, Workflow Compositor, and
Workbench/Foundry surfaces, other application surfaces, and
Environments views also use the
thread/turn control substrate:

```http
POST /v1/threads
GET  /v1/threads
GET  /v1/threads/{thread_id}
POST /v1/threads/{thread_id}/resume
POST /v1/threads/{thread_id}/fork
POST /v1/threads/{thread_id}/turns
GET  /v1/threads/{thread_id}/turns
GET  /v1/threads/{thread_id}/events
GET  /v1/threads/{thread_id}/events/stream
POST /v1/threads/{thread_id}/turns/{turn_id}/interrupt
POST /v1/threads/{thread_id}/turns/{turn_id}/steer
POST /v1/threads/{thread_id}/mode
POST /v1/threads/{thread_id}/model
POST /v1/threads/{thread_id}/reasoning
POST /v1/threads/{thread_id}/speed
POST /v1/threads/{thread_id}/control
GET  /v1/threads/{thread_id}/usage
POST /v1/threads/{thread_id}/context-budget
POST /v1/threads/{thread_id}/compaction-policy
POST /v1/threads/{thread_id}/compact
GET  /v1/threads/{thread_id}/snapshots
POST /v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-preview
POST /v1/threads/{thread_id}/snapshots/{snapshot_id}/restore-apply
```

These endpoints are operator/runtime controls over the same substrate, not a
second chat runtime.

CLI surface should mirror the API:

```bash
ioi agent run <goal>
ioi agent status <run_id>
ioi agent events <run_id>
ioi agent trace <run_id>
ioi agent export <run_id>
ioi agent verify <run_id>
ioi agent approve <run_id> <request_hash>
ioi agent cancel <run_id>
ioi runtime doctor
ioi tools list
ioi models list
```

CLI command handlers should stay thin: they may submit runtime requests, stream
events, render traces, and collect approvals, but daemon/runtime code owns
execution semantics, policy gates, receipts, replay, and canonical state updates.

## Runtime Envelopes

The daemon should use stable envelopes:

```text
IntentContract
RuntimePlan
RunRequest
TaskCapsule
RuntimeToolContract
ActionProposal
GateResult
NormalizedObservation
AgentRuntimeEvent
AuthorityScopeRequest
PolicyDecision
HypervisorWorkQueue
HypervisorWorkItem
HypervisorWorkRun
HypervisorWorkRunConversationProjection
HypervisorWorkRunIntegrationStatus
HypervisorWorkRunReviewState
ModelInvocationReceipt
ToolExecutionReceipt
ArtifactRef
ReceiptBundle
OutputOwnershipPass
DeliveryBundle
QualityRecord
```

These envelopes must be stable across local, hosted, marketplace, CLI, UI, workflow, and benchmark surfaces.

The implementation may bridge the daemon API into a lower-level
`RuntimeAgentService` or other runtime service loop. That bridge is behind the
daemon/runtime-node profile. It does not change client ownership: SDK, ADK,
CLI/headless, optional TUI views, Workflow Compositor, Hypervisor App/Web
clients, Workbench/Foundry surfaces, other application surfaces,
Environments views, harnesses, and benchmarks remain
clients, builder frameworks, or projections.

## Delegated Agent Work Handling

The daemon owns the execution boundary for delegated agent work, whether it
starts from New Session, ioi.ai, Automations, Workbench, an API call, a pull
request, a schedule, or a webhook.

Canonical delegated-work shape:

```text
HypervisorWorkQueue
  intake and ordering policy for delegated work

HypervisorWorkItem
  normalized work request, code context, desired delivery, authority, and
  review contract

HypervisorWorkRun
  one execution attempt of a work item inside a governed session/environment
```

A WorkRun must bind desired phase, observed phase, selected HarnessProfile or
Agent Harness Adapter, model configuration, reasoning profile, project and
environment code context, authority grants, connector/MCP status, current
activity, conversation history, live stream, transcript, logs/support refs,
usage counters, output refs, review state, receipts, and Agentgres operation
refs.

Environment-resident agents are services behind the run. They may have a stable
service reference, package/binary/container hash, healthcheck, memory store,
ports, logs, and support bundle, but they do not become durable work truth and
do not hold durable authority. The daemon may start, stop, health-check,
comment, attach, or revoke them through admitted environment ops.

One-off handoff and durable automation are separate intents:

```text
one-off handoff
  create/admit a WorkItem and WorkRun, return a run ref once accepted, and
  avoid creating a reusable automation definition by default

durable automation
  create/update a versioned automation spec with triggers, limits, steps,
  review gates, and delivery contracts before starting runs
```

If a client times out after the daemon accepted a WorkRun, retrying the same
payload must be idempotency-aware so it does not create duplicate autonomous
runs. Clients should surface the run ref and environment/session link, then
poll or subscribe only when the user asks for live status.

## Event Model

The daemon should emit typed replayable events:

```text
session.started
turn.started
work_item.admitted
work_run.started
work_run.activity_changed
context.prepared
model.requested
model.completed
tool.proposed
policy.decided
approval.requested
tool.started
tool.progress
tool.completed
work_run.waiting_for_input
work_run.ready_for_review
work_run.comment_received
work_run.delivery_created
artifact.created
receipt.emitted
run.completed
run.failed
run.cancelled
work_run.completed
work_run.failed
work_run.cancelled
```

Events are not canonical by themselves. Agentgres-admitted state and the
applicable settlement owner are authoritative for their domains. Receipts bind
declared event or claim facts and assurance evidence; they are not correctness,
acceptance, or settlement by themselves.

## Relationship to Agentgres

The daemon writes/updates domain state through Agentgres-compatible APIs:

- run state;
- artifacts;
- receipts;
- delivery bundles;
- quality ledgers;
- worker invocations;
- contribution receipts;
- governed autonomous-system chain transitions;
- Hypervisor Node local settlement records.

The daemon must not maintain a separate canonical state store for application truth.

## Relationship to wallet.network

The daemon requests authority scopes from wallet.network.

It must not receive raw long-lived secrets where a scoped authority grant or operation-internal execution is possible.

Sensitive actions require:

- policy decision;
- authority lease;
- approval token when needed;
- exact request hash;
- expiry;
- revocation epoch.

## Runtime Privacy Profiles

1. **Local/private** — local Hypervisor, customer machine.
2. **Mutual Blind** — no TEE; redacted/minimized capsules, no final authority.
3. **Enterprise Secure** — TEE-attested node; sealed secret release.
4. **Hosted trusted** — IOI/provider-managed runtime under contractual trust.

## Anti-Patterns

Do not model the daemon/runtime layer as:

```text
SDK = runtime substrate
CLI/headless = private execution loop
TUI = separate first-class runtime/client lane
external CLI agent harness = Hypervisor client
Codex/Claude Code/Grok Build = runtime truth
Hypervisor App/Web/CLI-headless = runtime truth
Hypervisor Workbench/Foundry/provider views = runtime truth
Hypervisor Core = peer runtime beside the daemon
Default Harness Profile = peer daemon, only admissible harness, or meta-harness
selected harness/model = owner of workspace skills or memory
Authority Gateway adapter = total control over opaque third-party agents
runtime node = application-domain truth store
model reply = completed run proof
```

Correct model:

```text
daemon owns execution semantics
Hypervisor Core coordinates clients, surfaces, sessions, and adapters
clients request, inspect, steer, and approve
Workflow Compositor shapes high-level directed work
selected HarnessProfiles resolve scoped steps
Default Harness Profile is the reference scaffold/fallback profile
workspace skills and Agent Wiki / ioi-memory persist outside selected harnesses
Agentgres records operational truth
wallet.network authorizes effects
receipts and replay make work accountable
```

## Related Canon

- [`default-harness-profile.md`](./default-harness-profile.md):
  HarnessProfile semantics and Default Harness Profile reference
  scaffold/fallback behavior.
- [`api.md`](./api.md): public daemon/runtime API endpoints and action
  mediation.
- [`events-receipts-delivery-bundles.md`](./events-receipts-delivery-bundles.md):
  runtime event, receipt, trace, replay, and delivery objects.
- [`../hypervisor/core-clients-surfaces.md`](../hypervisor/core-clients-surfaces.md):
  Hypervisor Core, first-class clients, application surfaces, sessions, and
  adapters.
- [`../wallet-network/doctrine.md`](../wallet-network/doctrine.md): authority
  and approval substrate.
- [`../agentgres/doctrine.md`](../agentgres/doctrine.md): operational truth
  substrate behind daemon execution.

## Invariants

1. No effectful tool execution without a tool contract and risk class.
2. No sensitive action without a persisted policy decision.
3. No policy-required approval without exact-scope approval token.
4. No raw secret exposure to agents.
5. No final effect from untrusted DePIN nodes without trusted verification/settlement.
6. No split runtime path for workflow vs agent vs benchmark vs CLI execution.
7. No long-running job without deadline, cancellation, and progress events.
8. No compute-node architecture where the SDK replaces the Hypervisor Daemon runtime
   profile as execution owner.
9. No TUI-only runtime controls; TUI controls must map to daemon/domain APIs
   and remain an optional presentation of CLI/headless controls.

## One-Line Doctrine

> **The Hypervisor Daemon is where Web4 work executes; Agentgres remembers it, authority is granted by local/domain governance or wallet.network according to risk boundary, and IOI L1 settles what matters.**

## CLI Product Context Module

The `IOI CLI` v1.1 product-spec module (the former `docs/specs/ioi-cli.md`:
command families, natural-language-to-plan, artifact/evidence/receipt,
policy, publish, and execution-path detail) is archived verbatim at
[`../../_archive/specs/ioi-cli-v1-1-product-spec.md`](../../_archive/specs/ioi-cli-v1-1-product-spec.md).
Its own status was `Proposed revision`; where it disagrees with the
canonical doctrine above, the doctrine above wins. The CLI/headless client
boundary is owned by this file and [`api.md`](./api.md).
