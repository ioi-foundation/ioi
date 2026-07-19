# Connectors, Tools, and Authority-Aware Registry Specification

Status: canonical architecture authority.
Canonical owner: this file for connector/tool registry doctrine and the
local-agent-pairing-to-gateway boundary; low-level tool contracts and connector
mappings live in [`connector-and-tool-contracts.md`](./contracts.md).
Supersedes: older flattened capability-registry wording when it conflicts with primitive capability and authority scope tiers.
Superseded by: none.
Last alignment pass: 2026-07-16.
Doctrine status: canonical
Implementation status: partial (connector estate, capability leases, and MCP gateway built; registered RuntimeToolContract information-flow ceilings, the non-MCP HTTP connector vertical, and live MCP tool-call/list propagation are built; MCP resource/prompt/elicitation/task/App, OutcomeRoom, inbound connector/webhook, and remaining browser/computer-use propagation are explicit 3B2 gaps; `LocalAgentPairingSessionEnvelope`, room-admitted local-agent gateway issuance, and the semantic-data chain remain planned/partial)
Implementation refs:
  - `crates/node/src/bin/hypervisor_daemon_routes/`
Last implementation audit: 2026-07-16 (information-flow Cut 3B1 propagation)

## Canonical Definition

**Connectors expose external systems as typed, permissioned, receipted guest
capabilities inside the Hypervisor Daemon runtime hypervisor.**

Tools are not arbitrary function calls. Every effectful tool must have a contract, risk class, primitive capability requirements, authority scope requirements, policy target, and receipt obligation.

Hypervisor clients and application surfaces may display connector readiness,
auth posture, dry-run previews, approval requests, run state, and receipts.
They must not hold connector secrets or call provider APIs directly. Connector
execution flows through daemon tool calls, wallet.network authority, policy
decisions, and receipts.

## Product Surface Doctrine

`Connectors / Tools / MCP` is Developer Console's registry facet — a legacy
family label that maps to the Developer Console application (the alias
authority in `_meta/vocabulary.md`), never a separate catalog card. It
reaches the Applications catalog through Developer Console and renders inside
the singular Open Application slot when Developer Console is active.

The surface may expose:

```text
tool discovery
native connector readiness
MCP server readiness
workflow-as-tool subgraphs
input/output schemas
risk classes
primitive capability requirements
wallet/provider authority requirements
policy explanations
approval previews
adapter health
receipt obligations
tool quality signals
```

This surface is not Settings and not an authority bypass. It helps builders and
operators understand what a tool can do, what it needs, why it is blocked, and
what proof it must emit. Actual invocation still flows through Hypervisor Core,
the daemon, wallet.network, Agentgres, and receipt/replay boundaries.

The Hypervisor Operator Plane may consume these same tool/MCP contracts to
operate application surfaces and Hypervisor-level product state. Child sessions
may request or propose those operations, but effectful host/platform actions
must be admitted by the daemon and authorized through wallet.network. MCP is a
surface contract, not a host mutation bypass.

ioi.ai connector/auth escalation is a handoff over this same registry. ioi.ai
may detect a missing connector, expired grant, insufficient scope, or required
approval; explain the requested tool, risk, scope, and preview posture; and ask
wallet.network for authority. It must not hold provider secrets, call provider
APIs directly, or invent an ioi.ai-only connector runtime. Actual invocation
still flows through `RuntimeToolContract` or MCP contracts, daemon admission,
wallet.network authority, Agentgres refs, and receipts.

Connector entitlement boundary:

```text
connecting an app != paid connector access by default
authority grant != connector toll booth
private/background/sensitive connector execution may require paid managed runtime
```

Adding a connector, granting ordinary authority, or previewing readiness should
not by itself be treated as a paid feature. A paid handoff is legitimate when
the requested work needs managed connector brokerage, background automation,
external mutation, private connected-app processing, cTEE/TEE/customer-boundary
placement, no-provider-trust routing, audit/replay retention, or Work Credit
budget beyond the included plan.

Product surfaces should present this as the two-mode managed execution choice
rather than a generic connector upsell. `Standard` keeps the private-native
runtime substrate and may use disclosed provider-trust model routes. `Private`
requires the stricter no-provider-trust model route plus local, BYO private
node, customer-boundary/customer-cloud, cTEE, TEE, or another custody-proven
path. The selected path must still preserve scoped authority, secret custody,
dry-run/approval policy, receipts, and revocation.

The registry is also the brokered capability substrate for harness/model choice.
Whether a run is platform-selected, MoW-routed, or user-directed toward a
specific harness, model route, worker, or managed agent, the selected participant
receives only a scoped tool/MCP capability manifest. It does not receive raw
connector credentials, provider tokens, unbounded tool discovery, or direct
provider API access. The manifest binds allowed tools, MCP gateway profiles,
connector refs, risk ceilings, authority requirements, policy posture, receipt
obligations, and revocation paths.

## Hypervisor MCP Gateway

The **Hypervisor MCP Gateway** is the authority-scoped compatibility gateway
that lets external agents and harnesses use selected Hypervisor capabilities
through MCP without entering the Hypervisor UI.

It is not a "master MCP," root administrator, durable API key, direct connector
path, or host mutation bypass. It is a profile-bound projection over registered
Hypervisor tools, surfaces, sessions, automations, Foundry jobs, receipts, and
operator-plane requests.

Canonical flow:

```text
external agent or harness
  -> Hypervisor MCP Gateway profile
  -> exposed MCP tool manifest
  -> RuntimeToolContract or surface MCP contract
  -> daemon admission
  -> wallet.network authority or approval
  -> Agentgres operation, projection, receipt, and replay
```

Gateway profiles should be explicit:

```text
discovery_readonly
  list available capabilities, models, workers, projects, sessions, tools,
  readiness, policy explanations, and receipts without effectful actions

project_session
  create or request sessions, inspect project/session state, attach authorized
  context refs, and read run progress under project policy

connector_preview
  inspect connector readiness, request auth escalation, and run dry-run previews
  without mutating external systems

operator_proposal
  submit platform or application-surface changes as proposals through the
  Hypervisor Operator Plane; no direct host/platform mutation

effectful_approved
  call effectful tools only with required authority grants, approval posture,
  idempotency, policy admission, and receipt obligations

foundry_eval_training
  draft or start authorized Foundry jobs, evals, dataset-factory runs, training
  pipelines, experiment cycles, and model/worker promotion candidates

receipts_replay_proof
  inspect authorized events, trace bundles, receipts, replay, delivery bundles,
  and proof/settlement drilldowns
```

Packages, application-surface releases, adapter manifests, and System manifests
may carry immutable `MCPGatewayRequirementEnvelope` refs when MCP compatibility
is specifically required. GoalRunProfiles, WorkflowTemplates, and
SkillManifests remain transport-neutral and declare semantic capabilities,
tools, resources, context, and input contracts instead. The concrete
Hypervisor MCP Gateway profile is created later for one admitted subject and use, freezes
the resolved requirement set and exposure-manifest hashes, and binds scope,
privacy, budget, expiry, revocation, and an admission receipt. Narrowing,
suspension, quarantine, expiry, or revocation may reduce effective access
through lifecycle/policy state without rewriting that revision; any changed
declared exposure creates a successor, and privilege widening requires fresh
admission.

Protocol objects stay subordinate to canonical IOI owners: tools normalize to
`RuntimeToolContract`; resources to policy-bound views, artifacts, or memory
projections under `ContextLease`; prompts to untrusted import inputs;
elicitation to typed user input with separate wallet approval when authority is
required; tasks to opaque handles on `HarnessInvocation`; and Apps to sandboxed
`extension_application` surfaces. An MCP server session or task is never
GoalRun, WorkRun, authority, state-root, or receipt truth. The field-level
mapping is owned by [`contracts.md`](./contracts.md#mcp-normalization-boundary).

Every gateway-exposed MCP tool must declare the backing contract ref, profile,
risk class, primitive capabilities, required authority scopes, readiness state,
dry-run/approval policy, privacy posture, rate/budget limits, receipt
obligations, and revocation path. Gateway manifests may simplify labels for
external harnesses, but they must not hide authority, policy, or receipt
requirements.

The gateway exists to make Hypervisor useful from Codex-like tools, local agents,
enterprise agents, aiagent.xyz workers, CI agents, and third-party harnesses
without giving those agents ambient authority. It should increase external
utility while preserving the same daemon, wallet.network, Agentgres, cTEE,
receipt, and replay boundaries as native Hypervisor clients.

Connector registration and invocation preserve a separate information-flow
boundary. Each HTTP adapter tool binds one exact RuntimeToolContract revision
with data-class and destination allowlists. Request arguments carry a versioned
`InformationFlowLabel`; the daemon evaluates it before wallet/credential use
and again immediately around the external invoker. The live MCP backend applies
the same parent-aware compilation to `tools/call` and `tools/list` before
`McpManager`, then labels results as untrusted tool output. Connector and tool
outputs re-enter context as provenance-bearing untrusted inputs until an
explicit mapping and integrity decision says otherwise. Output-schema
validation never makes embedded instructions authoritative. MCP resources,
prompts, elicitation, tasks, Apps, OutcomeRoom, inbound webhooks, and other
connector families remain explicit Cut 3B2 gaps rather than inferred coverage.

### Local-agent pairing to gateway admission

The screenshot-style **Connect local agent** flow is an ingress convenience over
the same gateway, not a new authority or collaboration protocol. ioi.ai may
embed the modal in a Goal Space, but Hypervisor owns the local adapter, daemon
pairing, candidate key/origin binding, and gateway issuance boundary. The
canonical pairing object is
[`LocalAgentPairingSessionEnvelope`](../../foundations/common-objects-and-envelopes.md#localagentpairingsessionenvelope);
deployment-local lifecycle handling is owned by
[`identity-access-and-metering.md`](../hypervisor/identity-access-and-metering.md#local-agent-pairing-sessions).
aiagent.xyz owns only a later explicit private reusable Worker record or public
package/listing/benchmark/routing-eligibility handoff; pairing never publishes
the agent automatically.

```text
authenticated user selects Connect local agent
  -> Hypervisor returns one copyable bootstrap command/prompt plus a one-time,
     hash-at-rest, expiring challenge/device code
  -> local candidate generates a signing key and proves the key + origin binding
  -> pairing authenticates the candidate but grants no room or tool authority
  -> candidate reads only OutcomeRoomDiscoveryEnvelope, submits its typed
     WorkerComposition proposal, then submits RoomParticipationRequestEnvelope
  -> declared room owner admits or rejects under room policy
  -> admitted RoomParticipantLeaseEnvelope
  -> Hypervisor issues a scoped, expiring, revocable MCP gateway profile bound
     to pairing session, candidate key, origin, participant lease, room, policy,
     privacy, rate, budget, and receipt obligations
```

That branch is specific to `room_guest`. For `private_worker` and
`organization_worker`, completed pairing may feed a separate private registry
admission. A later direct call, Session, Automation, or WorkRun receives a
gateway profile only after that concrete invocation passes its own context,
tool, resource, budget, privacy, policy, and authority admission. It binds the
active worker registration and invocation scope rather than inventing an
OutcomeRoom or participant lease. If the reusable worker later joins a room,
the ordinary room-participation request and lease become mandatory.

The bootstrap payload may contain public discovery refs, endpoint location,
pairing expiry, adapter instructions, and the one-time challenge. It must not
contain a broad organization read/write token, raw model/provider or connector
credentials, private room context, a wallet grant, a durable API secret, or an
unbounded tool manifest. After candidate binding, subsequent traffic uses the
candidate-generated key/origin binding; the one-time device code cannot become
the continuing credential.

Prompt-only compatibility is allowed for agents that cannot run a native
adapter or local sidecar, but its contract is deliberately narrow:

```text
prompt_only_proposal
  may: read the permitted discovery projection, request admission, submit
       tainted messages/artifact refs/proposals through the declared path
  may not: receive ambient room context, call effectful tools, hold connector or
           provider credentials, mutate shared truth, claim instrumented
           execution, earn payout/reputation from pairing alone, or publish
           itself to aiagent.xyz
```

The host may verify and admit a prompt-only proposal under the ordinary
WorkResult/evidence path. That verifies the admitted result under its named rule;
it does not retroactively make the proposing agent or its hidden runtime
verified. Stronger tool access requires a signed candidate plus the applicable
admitted use and matching gateway profile: a participant lease for
`room_guest`, or an active private/organization registration plus a separately
admitted invocation, Session, Automation, or WorkRun for a reusable worker.
Effectful access additionally requires the action-specific authority and daemon
admission already required by the backing `RuntimeToolContract`.

## Readiness and Escalation States

Connector, tool, and MCP readiness must be explicit enough for Hypervisor
surfaces, ioi.ai handoffs, Automations, and child sessions to explain why an
operation can run, preview, wait, or fail. A client may simplify the labels, but
the registry state should distinguish:

```text
unknown
  the connector/tool has not been checked in the current context

ready
  requirements are satisfied for the requested operation class

not_connected
  no provider/account binding exists

auth_required
  identity exists, but wallet/provider authority has not been granted

expired
  the grant, lease, token, or provider binding is no longer valid

scope_insufficient
  an active grant exists, but it lacks the requested operation scope

approval_required
  policy permits the operation only after human, org, quorum, or step-up review

dry_run_required
  the tool must produce a preview before effectful execution can be requested

policy_blocked
  policy denies the operation unless policy or organization posture changes

degraded
  the connector/tool can partially function, but health, quota, provider status,
  schema drift, or quality posture requires disclosure

revoked
  authority or connector binding was intentionally withdrawn
```

Escalation must preserve the distinction between "needs authority", "needs a
preview", "needs review", and "is blocked by policy." More authentication must
not be presented as the fix for a policy-blocked action, and a dry-run preview
must not be treated as authorization to mutate external state.

## Connector Examples

```text
gmail.search
gmail.read_thread
gmail.create_draft
gmail.send_with_approval
calendar.find_availability
calendar.create_event
drive.search_docs
drive.read_doc
github.open_issue
github.comment_pr
slack.post_message
slack.import_thread
commerce.create_cart_draft
commerce.submit_order
blender.render_preview
freecad.export_step
```

## RuntimeToolContract

The contract field set is owned by [`contracts.md`](./contracts.md); this
doctrine file does not carry a second definition. Every effectful tool
declares, at minimum: identity (id, namespace, display name, version), input
and output schemas, a `risk_class` from the canonical ladder, a concurrency
class, timeout and cancellation behavior, required `prim:*` capabilities and
`scope:*` authority, semantic-data refs, approval-scope fields, required
evidence, a redaction policy, and an owner. See
[`contracts.md`](./contracts.md) for the canonical shape and a worked
`gmail.send` example.

## Risk Classes

The canonical risk-class ladder is owned by
[`../../foundations/canonical-enums.md`](../../foundations/canonical-enums.md).
Earlier revisions of this file used the deprecated aliases `read_only`,
`external_draft`, `commerce_cart`, `commerce_order`, `funds_transfer`, and
`credential_touching`; the alias table in `canonical-enums.md` maps each to
its canonical class. New contracts use canonical members only.

## Connector Authority

Connector secrets live in wallet.network.

The runtime receives:

- operation-scoped authority scope/lease;
- short-lived access token if absolutely necessary;
- internal execution by wallet/guardian when possible.

It should not receive raw refresh tokens or long-lived secrets.

## Connector Mappings and Data Recipes

Connectors expose provider data. They do not define the domain by themselves.

For training, evaluation, ontology-aware projections, MoW routing, or service
delivery, connector outputs should flow through:

```text
RuntimeToolContract
→ ConnectorMapping
→ DataRecipe
→ TransformationReceipt
→ ontology-bound Agentgres objects / datasets / projections
```

ConnectorMapping declares how provider fields, files, events, and actions map
to canonical object models and authority scopes. DataRecipe declares how mapped
source material is extracted, redacted, normalized, deduped, validated, linked,
and exported.

This prevents the platform from treating a Gmail thread, CRM row, Drive file,
GitHub issue, or spreadsheet as domain truth merely because a connector could
read it.

## Capability Tiering

Connector/tool contracts must separate two tiers, and the tiers are named as
distinct contract fields — never flattened back into one capability bag:

- Primitive execution capabilities (`prim:*`) describe runtime feasibility,
  isolation, and risk boundaries. On the runtime tool contract this is the
  `primitive_capabilities` field (serialized in the contract document as
  `primitive_capabilities_required`).
- Authority scopes (`scope:*`) describe wallet/provider admission for a
  concrete operation or account. On the runtime tool contract this is the
  `authority_scope_requirements` list (serialized as
  `authority_scopes_required`); a connector action mapping binds one
  operation's admission as its singular `authority_scope_required`.

The older flattened capability-lease projection field has been removed from
the runtime tool contract. Compatibility adapters must map explicitly into one
of these two tiers instead of recreating a generic capability bag; a lease is
how an authority scope is GRANTED at runtime (the CapabilityLease gateway),
not a third contract field.

MCP tools, external agent tools, and workflow-as-tool subgraphs must compile to
the same contract split:

```text
RuntimeToolContract
primitive capabilities
authority scopes
policy decision
receipt obligation
```

No MCP server or external tool bridge may become a shortcut around daemon
admission, wallet.network authority, Agentgres projection, or receipt policy.

No Hypervisor MCP Gateway profile may expose an unbounded "all tools" or "all
surfaces" authority. Broad discovery can exist, but preview, proposal, and
effectful execution must be narrowed by profile, project/session context,
authority scope, policy, privacy posture, budget/rate limit, and revocation
state.

Local-agent pairing does not weaken that rule. A
`LocalAgentPairingSessionEnvelope` may resolve only to candidate authentication;
the gateway profile is a separate post-admission object and must bind the exact
applicable admission basis and scope leases: participant lease for a room guest,
or active registration plus concrete invocation/session/run admission for a
reusable worker. Before completion, pairing expiry or revocation fails closed
and creates no partial grant. After admission, pairing history is immutable
lineage rather than the continuing gateway credential: room retirement,
participant quarantine/revocation, claim release, origin change, key rotation,
or an explicit security revocation must follow the downstream object's policy
and propagate to dependent gateway/session/run refs. Pairing revocation alone
does not erase an independently admitted composition, request, contribution, or
lease.

## Tool Registry

The tool registry should:

- discover native tools;
- register connector tools;
- register MCP tools;
- register workflow-as-tool subgraphs;
- expose schemas;
- expose risk classes;
- expose primitive capability and authority scope requirements;
- expose policy explanations;
- feed tool-quality models;
- emit governed tool-analytics signals for usage, latency, error class,
  missing-capability requests, redacted argument shape, client/session flow, and
  quality feedback.

Tool analytics improve routing, evals, registry quality, and missing-capability
planning. They do not replace receipts and they do not authorize tool use.

## Workflow Integration

Connectors should add tools to the harness/canvas through the registry, not through hardcoded calls.

Workflow nodes should bind to `RuntimeToolContract`.

## Commerce Connector Policy

High-risk commerce tools should be split:

```text
cart/search/draft     = medium risk
submit/purchase/order = high risk, human approval required
```

Generic example:

```yaml
commerce.create_cart_draft:
  risk_class: commerce   # cart/draft stage; approval preview binds cart contents
  approval_required: false_or_policy

commerce.submit_order:
  risk_class: commerce   # order placement stage
  approval_required: true
```

## Local Creative Connectors

Blender/CAD connectors can be earlier because they are local artifact-production tools with lower external-effect risk.

They should still emit artifacts and receipts.

## Invariants

1. No effectful tool without contract.
2. No connector secret outside wallet.network unless explicitly and temporarily released.
3. No high-risk action without approval and required authority.
4. No tool result trusted without output schema validation.
5. No marketplace worker may bypass tool policy.
6. Tool quality should be measured and fed back into routing over time.
7. No connector payload may become training, evaluation, projection, routing,
   or service truth without the applicable ConnectorMapping, DataRecipe,
   policy-bound data view, and receipts.
8. No MCP server, external agent tool, or workflow-as-tool subgraph may bypass
   `RuntimeToolContract`, primitive capability, authority scope, policy, and
   receipt requirements.
9. No child session MCP/tool exposure may mutate Hypervisor host or platform
   state directly; host/platform effects route through declared application
   surface contracts and the Hypervisor Operator Plane.
10. No local-agent bootstrap may expose a broad org read/write token, raw
    provider credential, ambient room context, master MCP surface, or reusable
    pairing code.
11. Pairing authenticates a candidate and nothing more. A room guest requires
    typed room admission and a participant lease; a reusable private or
    organization worker requires active registration plus concrete
    invocation/session/run admission. Only the applicable admitted scope may
    precede a scoped gateway profile, and effectful calls still require their
    own authority.
12. Prompt-only local agents remain low-assurance proposal sources; pairing
    cannot label them instrumented, independently verified, payable, reputable,
    or marketplace-published.

## One-Line Doctrine

> **Connectors do not give agents secrets. They give agents authority-scoped tools with primitive runtime constraints.**
