# Connector and Tool Contracts

Status: canonical low-level reference.
Canonical owner: this file for RuntimeToolContract, ConnectorMapping
references, immutable MCP gateway requirements, subject-scoped Hypervisor MCP
Gateway profiles including post-pairing room-admission bindings, protocol
normalization, tool API, connector API, source-control publication effects,
risk classes, and approval rules.
Supersedes: older flattened tool capability examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-08-24.
Doctrine status: canonical
Implementation status: partial (the RuntimeToolContract owner, immutable native/seeded-connector/live-MCP registry, shared final-invoker admission, pre-invocation receipts, information-flow checks, daemon tool catalog, MCP route classification, and canonical live MCP tool invocation are implemented; non-tool MCP primitives and subject-scoped gateway profiles fail typed-unavailable, while estate-wide IFC propagation/enforcement, general inbound connector subscriptions, OutcomeRoom discussion/artifact resolution, remaining browser/computer-use families, `LocalAgentPairingSessionEnvelope` bindings, room-admitted local-agent gateway issuance, a bound review-request host surface, and the whole of `ioi.scm-publication-effect.v2` remain planned)
Implementation refs:
  - `crates/services/src/agentic/runtime/runtime_tool_contract_registry.rs`
  - `crates/services/src/agentic/runtime/service/handler/execution/runtime_tool_admission.rs`
  - `crates/services/src/agentic/runtime/tools/contracts.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs`
  - `crates/node/src/bin/hypervisor_daemon_routes/operability_routes.rs`
  - `apps/hypervisor/scripts/verify-mcp-transport-normalization.mjs`
Last implementation audit: 2026-08-24 (`RuntimeAgentService` resolves a released immutable contract after deterministic tool normalization and before prepare or invocation; live MCP descriptors enter that registry atomically and live calls converge on the same final invoker; all 36 externally reachable MCP routes are startup-classified; non-tool primitives and an unbound external gateway fail typed-unavailable without minting authority or receipt identity; canonical harness-chain convergence remains separately owned work; `ScmPublicationEffect` v1 has a conforming runtime path whose refusal branches are pinned by tests, with the review-request host surface still unbound; `ScmPublicationEffect` v2 remains registered substrate only)

## Purpose

Connectors expose typed, permissioned, receipted guest capabilities into
workflows, workers, and Hypervisor. Tools are not ambient authority; every tool
has a contract, risk class, primitive capability requirements, authority scope
requirements, and receipt obligations. Effectful connector calls execute through
the Hypervisor Daemon hypervisor/control plane, not from Hypervisor clients,
application surfaces, or extension hosts.

## RuntimeToolContract

```json
{
  "tool_id": "tool://gmail.send",
  "revision_ref": "tool://gmail.send/revision/1.0.0",
  "predecessor_revision_ref": null,
  "content_hash": "sha256:...",
  "namespace": "gmail",
  "display_name": "Send Gmail message",
  "version": "1.0.0",
  "input_schema": {},
  "output_schema": {},
  "risk_class": "external_message",
  "effect_class": "external_message",
  "concurrency_class": "safe_parallel | resource_scoped | exclusive | serialized",
  "timeout": {
    "default_ms": 30000,
    "max_ms": 120000
  },
  "primitive_capabilities_required": ["prim:net.request"],
  "authority_scopes_required": ["scope:gmail.send"],
  "semantic_data": {
    "ontology_refs": [],
    "connector_mapping_refs": [],
    "input_object_model_refs": [],
    "output_object_model_refs": []
  },
  "analytics_policy": {
    "emit_usage_signal": true,
    "capture_intent": "explicit | inferred | none",
    "capture_arguments": "none | schema_only | redacted | full_private",
    "missing_capability_signal": true,
    "quality_signal_refs": []
  },
  "approval_required": true,
  "evidence_required": ["request_preview", "provider_response"],
  "redaction_policy": "redact_body | hash_only | full_private",
  "data_class_allowlist": ["public", "internal", "confidential"],
  "egress_policy": {
    "default": "deny | allow_declared",
    "allowed_destination_patterns": ["https://gmail.googleapis.com/gmail/v1/*"]
  },
  "owner": "connector://gmail",
  "registry_lifecycle_ref": "agentgres://object/tool/gmail.send",
  "registry_status": "draft | released | deprecated | revoked"
}
```

Every released RuntimeToolContract revision is immutable and
content-addressed. `registry_lifecycle_ref` and `registry_status` are excluded
projections; a schema, risk/effect, capability, authority, evidence, or policy
change creates a successor revision. Admission and package pins use the exact
`revision_ref` plus `content_hash`, never a mutable tool family ID alone.

`risk_class` (the class assessed at admission) and `effect_class` (the effect
actually performed) both draw their members from the canonical risk-class
ladder in
[`../../foundations/canonical-enums.md`](../../foundations/canonical-enums.md);
neither field defines its own enum.

Tool analytics are improvement signals, not execution truth. They may record
call volume, latency, error class, missing-capability requests, intent,
redacted argument shape, and quality labels, but consequential proof still
comes from daemon-admitted events, wallet authority, Agentgres state, and
receipts.

Every RuntimeToolContract revision declares both the data classes it may
receive and the exact destination patterns it may contact. `prim:net.request`
is therefore never ambient network authority. A missing data-class allowlist,
missing destination declaration, default deny, destination mismatch, or
information-flow label outside either allowlist fails closed before the
external invoker. Connector adapter entries bind their method/path mapping to
one exact nested `runtime_tool_contract` revision; the adapter mapping is not a
substitute tool contract.

### Current runtime alignment

The daemon's `RuntimeAgentService` owns one immutable registry of released
native tool revisions plus the explicitly seeded Google Workspace and
wallet-mail connector revisions. Each snapshot retains the exact JCS hash
material, generated-schema projection, revision/hash indexes, admission receipt
reference, head, and revocation state. `GET /v1/tools` projects that same seeded
registry. Dynamic service, skill, and MCP candidates without an admitted head
are hidden at discovery and refused again at invocation.

`handle_action_execution` is the shared admission point for queue delivery,
delegated workers, and approval resumes. It runs after any deterministic tool
rewrite and before prepare, policy dispatch, adapter dispatch, or final
invocation. Admission resolves the released head, compares the daemon-observed
effect boundary, requires an exact worker-assignment tool grant or a compatible
resolved-intent grant, enforces declared data class and destination, and writes
an idempotent pre-invocation receipt binding the exact session, step, normalized
arguments, contract revision/hash, `prim:*` grants, `scope:*` grants, and grant
source. It does not claim that the receipt proves a later invocation or effect.

This closure now includes live MCP tool descriptors and calls: descriptors are
atomically admitted under the server receipt and the canonical thread-scoped
import/add routes start explicitly live stdio configurations, bind the resulting
immutable revision refs into the owning thread's daemon record, and expose only
those bound descriptors through canonical search/detail/invoke. Disable/remove
deterministically tear down transport routing; enable restarts the retained live
configuration, reusing an identical contract or admitting a predecessor-bound
successor when the descriptor changed. The invoke route re-enters this same final
invoker. Resource, prompt, elicitation,
external-task, App, serve, and unbound external-gateway surfaces remain explicit
typed-unavailable mappings. Consolidating the independent session/harness routes
into the canonical mounted execution chain remains separate work; that absence
does not permit an uncontracted call through `RuntimeAgentService`.

## MCP Gateway Requirement

`MCPGatewayRequirementEnvelope` is the immutable, package-safe declaration of
what an eventual consumer must be able to discover or invoke. It names
semantic requirements and ceilings; it has no subject, credential, lease,
session, authority grant, or live endpoint.

```yaml
MCPGatewayRequirementEnvelope:
  schema_version: ioi.mcp-gateway-requirement.v1
  requirement_id: mcp-gateway-requirement://...
  revision_ref: mcp-gateway-requirement://.../revision/...
  predecessor_revision_ref: mcp-gateway-requirement://.../revision/... | null
  content_hash: hash
  owner_ref: ioi://publisher/... | org://... | project://... | system://...
  consumer_class_refs: []
  required_runtime_tool_contract_refs: []
  required_resource_projection_contract_refs: []
  permitted_prompt_import_contract_refs: []
  required_elicitation_contract_refs: []
  external_task_compatibility_refs: []
  extension_application_requirement_refs: []
  maximum_risk_class: canonical risk class
  authority_scope_requirement_refs: []
  privacy_budget_rate_and_retention_policy_refs: []
  transport_and_protocol_compatibility_refs: []
  allowed_override_schema_ref: schema://... | null
  provenance_and_evaluation_refs: []
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | released | deprecated | revoked
```

A Package, application-surface release, adapter manifest, or System manifest
may reference this requirement when MCP compatibility is itself required.
GoalRunProfile, WorkflowTemplate, and SkillManifest instead declare semantic
capability, tool, resource, context, or input requirements and remain transport-
neutral. Admission resolves the MCP-specific requirement to native
capabilities, service modules, connectors, or one concrete gateway profile.
Packaging the requirement never creates that profile and never grants its
requested scopes.
The released body and `content_hash` are immutable. Registry lifecycle/status
is an excluded projection; any content change creates a successor revision.

## Hypervisor MCP Gateway Profile

The Hypervisor MCP Gateway exposes selected RuntimeToolContracts, surface MCP
contracts, session actions, Foundry actions, and receipt/replay views to external
agents or harnesses. The gateway profile is the contract that limits what a
given MCP consumer can discover, preview, propose, or execute.

```json
{
  "gateway_profile_id": "mcp_gateway://project-auditor-readonly",
  "profile_revision_ref": "mcp_gateway://project-auditor-readonly/revision/1",
  "predecessor_profile_revision_ref": null,
  "profile_content_hash": "sha256:...",
  "resolved_requirement_revision_refs": ["mcp-gateway-requirement://.../revision/..."],
  "resolved_requirement_set_hash": "sha256:...",
  "exposure_manifest_hash": "sha256:...",
  "display_name": "Project Auditor Read-only Gateway",
  "audience": "external_agent | ci_agent | marketplace_worker | enterprise_agent | local_harness",
  "profile_kind": "discovery_readonly | project_session | connector_preview | operator_proposal | effectful_approved | foundry_eval_training | receipts_replay_proof",
  "subject_ref": "agent://external/runtime-auditor",
  "local_agent_pairing_session_ref": "local-agent-pairing://... | null",
  "candidate_public_key_ref": "key://... | null",
  "project_refs": ["project://ioi"],
  "session_refs": [],
  "outcome_room_ref": "outcome-room://... | null",
  "room_participant_lease_ref": "participant-lease://... | null",
  "room_admission_decision_ref": "decision://... | receipt://... | null",
  "worker_registration_ref": "worker-registration://... | null",
  "admission_basis": "not_applicable | room_guest | registered_worker_invocation",
  "invocation_scope_refs": ["session://... | automation-run://... | work_run://... | participant-lease://..."],
  "pairing_execution_posture": "not_applicable | instrumented_adapter | prompt_only",
  "pairing_contribution_lane": "not_applicable | instrumented_candidate | proposal_only",
  "surface_refs": ["surface://connectors-tools-mcp", "surface://receipts-replay"],
  "exposed_tools": [
    {
      "mcp_tool_name": "hypervisor.project.inspect",
      "backing_contract_revision_ref": "tool://project.inspect/revision/1",
      "backing_contract_content_hash": "sha256:...",
      "contract_kind": "runtime_tool_contract | surface_mcp_contract | operator_plane_contract",
      "risk_class": "read",
      "effect_class": "read",
      "readiness": "ready",
      "dry_run_required": false,
      "approval_required": false,
      "authority_scopes_required": ["scope:project.read"],
      "receipt_obligations": ["ToolExecutionReceipt"]
    }
  ],
  "exposed_resources": [
    {
      "mcp_resource_uri": "hypervisor://project/ioi/summary",
      "backing_projection_ref": "view://... | artifact://... | memory_projection://...",
      "required_context_lease_ref": "context_lease://...",
      "redaction_policy_ref": "policy://..."
    }
  ],
  "exposed_prompt_import_contract_refs": ["schema://mcp-prompt-import/..."],
  "elicitation_contract_refs": ["schema://typed-user-input/..."],
  "external_task_contract_refs": ["schema://external-invocation-handle/..."],
  "extension_application_refs": ["surface://extension/..."],
  "authority_client_ref": "wallet_client://...",
  "origin_binding_ref": "origin://...",
  "authority_scope_refs": ["scope:project.read"],
  "privacy_posture_ref": "privacy://redacted",
  "budget_policy_ref": "policy://gateway-budget",
  "rate_limit_ref": "policy://gateway-rate-limit",
  "quarantine_policy_ref": "policy://gateway-quarantine",
  "dependent_refs": ["session://...", "work_run://...", "connector://..."],
  "issued_after_required_admission": true,
  "prompt_only_proposal": false,
  "expires_at": "2026-05-02T12:00:00Z",
  "revocation_ref": "revocation://...",
  "quarantine_advisory_refs": [],
  "status": "active | expired | suspended | quarantined | revoked",
  "last_use_ref": "event://...",
  "manifest_ref": "mcp_manifest://...",
  "admission_decision_ref": "decision://...",
  "admission_receipt_ref": "receipt://...",
  "receipt_refs": []
}
```

Gateway profiles do not grant authority by themselves. They bind a manifest to
wallet.network authority clients, daemon admission, Agentgres refs, policy, and
receipt obligations. A gateway profile may expose a tool as discoverable while
still returning `not_connected`, `scope_insufficient`, `dry_run_required`,
`approval_required`, `policy_blocked`, or `degraded` for a particular operation.
If the bound authority client, origin, grant, lease, connector, or policy enters
`quarantined`, `revoked`, or `expired` state, the gateway profile must stop
effectful calls before provider mutation, emit a scoped failure explanation, and
propagate quarantine to dependent sessions, WorkRuns, connector calls, and
pending approvals named by admitted refs. Blast-radius reports must be derived
from admitted gateway/client/session/run records and receipts, not inferred from
untrusted logs alone.

The admitted profile revision freezes its resolved requirement set, exposure
manifest, subject, scope, policies, and expiry. Admission decision/receipt and
append-only receipt refs bind the already-computed `profile_content_hash` and
are excluded from it, along with status, revocation, quarantine advisories, and
last-use lifecycle projections. Those projections and upstream policy, lease,
or connector state may only reduce effective access. Any change to the
declared profile body creates a successor revision. Widening tools, resources,
scopes, subjects, projects, sessions, risk ceiling, budget, retention, or
expiry additionally requires a fresh admission; `PATCH` is never a privilege-
widening or in-place definition-edit shortcut.

### MCP normalization boundary

MCP is one replaceable transport and extension protocol. Canonical IOI owners
remain independent of MCP protocol versions:

| MCP surface | Canonical normalization |
|---|---|
| Tool | One admitted `RuntimeToolContract`; actual use still requires the invocation's authority, policy, budget, evidence, and receipt path. |
| Resource | `PolicyBoundDataView`, `ArtifactRef`, or `MemoryProjection` accessed under a `ContextLease`; a resource URI is neither truth nor access authority. |
| Prompt | User-selectable import input to a `SkillManifest`, `GoalRunProfile`, or invocation; always untrusted/tainted until schema, policy, and provenance checks pass. |
| Elicitation | Typed user-input or clarification request. An authority-bearing choice separately enters wallet.network approval; elicitation itself is not approval. |
| Task | Opaque external invocation handle recorded on `HarnessInvocation`; it never becomes `GoalRun`, `AutomationRun`, WorkRun, or receipt identity. |
| App | Sandboxed `extension_application` surface over admitted contracts; it owns no runtime truth, secrets, authority, or direct host mutation. |

An MCP server session, task handle, prompt name, or resource URI therefore may
be transport evidence, but it cannot replace IOI run identity, state roots,
ContextLeases, authority grants, policy decisions, or receipts. Protocol-
version adapters must normalize into these owners and fail typed-unavailable
when they cannot preserve the mapping.

### Local-agent pairing profile binding

[`LocalAgentPairingSessionEnvelope`](../../foundations/objects/bounded-system-genesis.md#localagentpairingsessionenvelope)
owns the exact one-time local-agent challenge/device-code, candidate key,
origin binding, bootstrap, target, contribution-lane, assurance, and pairing
lifecycle fields. Deployment-local handling belongs to
[`identity-access-and-metering.md`](../hypervisor/identity-access-and-metering.md#local-agent-pairing-sessions).
A gateway profile references that object; it never redefines pairing and cannot
be created merely because the candidate completed its challenge.

For every local-agent subject, profile admission must prove all of the
following:

```text
pairing session reached completed with the target-specific typed submissions
candidate public key, origin, and WorkerComposition match the pairing record
gateway tools and views are a subset of the admitted use, privacy, and policy
profile expiry does not outlive the applicable scope lease or authority
rate, budget, quarantine, receipt, and revocation policy are bound
```

The admission basis then depends on the pairing target:

```text
room_guest
  typed RoomParticipationRequestEnvelope was admitted
  active RoomParticipantLeaseEnvelope names the same candidate and room
  invocation_scope_refs includes that participant lease

private_worker | organization_worker
  active private/organization worker-registration record names the same
  WorkerComposition, candidate key, origin, owner, and visibility posture
  the concrete direct call, Session, Automation, WorkRun, or later room request
  passed its own invocation/admission path and contributes the applicable
  context, tool, resource, budget, and authority leases
```

A reusable worker does not need a fictitious room or participant lease for a
direct invocation. Conversely, its private registration is not ambient access:
it grants no tools, context, authority, or budget until the concrete use is
admitted. If that worker later joins an OutcomeRoom, the room-specific
participation request and participant lease are required like any other worker.

The one-time challenge or device code is not copied into the gateway profile and
never becomes its bearer credential. No profile may derive a broad organization
read/write scope, raw provider or connector credential, ambient room context,
master MCP surface, wallet grant, reputation, payout right, or aiagent.xyz
publication from pairing.

When `pairing_execution_posture` is `prompt_only`, the admitted profile must
also bind `pairing_contribution_lane: proposal_only`, set
`prompt_only_proposal: true`, and expose only the declared proposal/artifact
submission and permitted projection reads. It cannot expose an effectful
`RuntimeToolContract`, claim daemon-instrumented execution, or promote submitted
material without the ordinary isolation, evidence, verification, and
room/domain admission path. A later `instrumented_adapter` upgrade is a new
admitted profile revision, not an inferred assurance change.

## Hypervisor MCP Gateway API

```http
GET  /v1/mcp/gateway-requirements
POST /v1/mcp/gateway-requirements/resolve
GET  /v1/mcp/gateways
POST /v1/mcp/gateways
GET  /v1/mcp/gateways/{gateway_profile_id}
PATCH /v1/mcp/gateways/{gateway_profile_id}
POST /v1/mcp/gateways/{gateway_profile_id}/revoke
GET  /v1/mcp/gateways/{gateway_profile_id}/manifest
POST /v1/mcp/gateways/{gateway_profile_id}/call
GET  /v1/mcp/gateways/{gateway_profile_id}/events
GET  /v1/mcp/gateways/{gateway_profile_id}/receipts
```

Requirement authoring and release belongs to Studio/Packages and its registry
admission path; the resolver route only evaluates an exact immutable revision
against one proposed consumer/use. `POST /gateways` creates the admitted
subject-scoped result. `PATCH` may suspend, quarantine, expire, or revoke that
revision and may attach a deny-only policy overlay. A changed declared exposure
is represented by a successor; widening also repeats admission.

Effectful gateway calls should occur inside an admitted run or operator-plane
operation:

```json
{
  "gateway_profile_id": "mcp_gateway://project-auditor-readonly",
  "mcp_tool_name": "hypervisor.connector.gmail.trash_preview",
  "input": {},
  "run_id": "run://123",
  "authority_grant_id": "grant_123",
  "approval_id": "approval_123",
  "idempotency_key": "idem_...",
  "requested_receipt_shape": ["ToolExecutionReceipt", "PolicyDecisionReceipt"]
}
```

## ConnectorMapping

Connector mappings bind provider payloads and actions to IOI canonical domain
objects. A connector payload is source material; it is not domain truth until a
ConnectorMapping and, where consequential, a DataRecipe map it into an
ontology-bound object, dataset, or projection.

```json
{
  "connector_mapping_id": "mapping://gmail-quote-thread",
  "connector_id": "connector://gmail",
  "ontology_ref": "ontology://construction-estimating/v1",
  "source_schema_ref": "provider_schema:gmail.thread",
  "target_object_model_refs": ["object-model://Quote", "object-model://Approval"],
  "field_mappings": [
    {
      "source": "thread.messages[].body",
      "target": "Quote.source_text",
      "redaction": "pii_filter"
    }
  ],
  "action_mappings": [
    {
      "tool_id": "tool://gmail.create_draft",
      "canonical_action": "Approval.request_clarification",
      "authority_scope_required": "scope:gmail.create_draft"
    }
  ],
  "evidence_required": ["source_message_hash", "mapping_version", "redaction_receipt"],
  "redaction_policy_ref": "policy://redact-customer-contact"
}
```

## Tool API

```http
GET  /v1/tools
GET  /v1/tools/{tool_id}
POST /v1/tools/{tool_id}/dry-run
POST /v1/tools/{tool_id}/call
GET  /v1/tools/{tool_id}/policy
GET  /v1/tools/{tool_id}/receipts/{receipt_id}
```

Effectful calls should occur within a run:

```json
{
  "run_id": "run://123",
  "tool_id": "tool://gmail.send",
  "input": {},
  "authority_grant_id": "grant_123",
  "approval_id": "approval_123",
  "idempotency_key": "idem_..."
}
```

## Connector API

```http
GET  /v1/connectors
GET  /v1/connectors/{connector_id}
POST /v1/connectors/{connector_id}/auth/start
POST /v1/connectors/{connector_id}/auth/callback
GET  /v1/connectors/{connector_id}/tools
GET  /v1/connectors/{connector_id}/subscriptions
POST /v1/connectors/{connector_id}/subscriptions
DELETE /v1/connectors/{connector_id}/subscriptions/{subscription_id}
```

## Source-Control Publication

Two registered contracts stand in this family. Version 1 is the historical
record of the merged publication route and keeps its own narrower nonclaim set.
Version 2 is the owner anchor for publication as one durable logical operation
with recovery and reconciliation. The claim boundary between them is stated
under [ScmPublicationEffect v2](#scmpublicationeffect-v2) and is decided by
which contract a route is compiled against, never by which section a reader
reaches first.

### ScmPublicationEffect

This section is retained as historical evidence for
`ioi.scm-publication-effect.v1`, the contract the merged route implements. Its
three nonclaims are exactly the three it registered; it makes no statement about
retry, recovery, or reconciliation, and nothing below widens it. The v2 section
that follows does not edit this one.

`ScmPublicationEffect` is the immutable, receipted record of exactly one
source-control publication crossing: an enumerated, proposal-bound file set
advanced onto one admitted remote destination under an expected-head
compare-and-swap, with the publication and the review request carried as two
separately receipted sub-effects. It is the only shape in which the estate may
mutate a remote repository through a connector.

```text
schema_version
publication_effect_id / publication_effect_hash
work_subject:
  proposal_ref / proposal_hash / work_run_ref
authority:
  authority_grant_refs / authority_scope_refs
  capability_lease_ref / admission_receipt_ref
destination:
  resolution: admitted_connector_binding
  connector_ref / connector_revision_hash
  destination_binding_ref / destination_binding_hash
  repository_ref / target_ref / base_ref
change_set:
  change_set_kind: proposal_bound_file_set
  proposal_content_commitment
  base_revision_id
  files: [ path, change_kind, content_digest, proposal_ref ]
  file_set_digest
  resulting_revision_id
remote_cas:
  mechanism: expected_head_compare_and_swap
  remote_update_mode: expected_head_advance_or_refuse
  stale_head_disposition: refuse_never_overwrite
  target_ref_precondition: expected_head | must_not_exist
  expected_target_head / expected_base_head
  observed_at / observation_evidence_ref
  resulting_target_head / proof_ref
idempotency:
  idempotency_key
  submission_disposition:
    first_admission | converged_replay | refused_conflicting_replay
  prior_effect_ref / prior_effect_hash
effects:
  publication:
    effect_kind: scm_publication
    outcome: published | partially_applied | refused
    receipt_ref / refusal_code / evidence_refs
  review_request:
    effect_kind: scm_review_request
    outcome: opened | failed | refused | not_requested | not_attempted
    receipt_ref / refusal_code / evidence_refs
overall_outcome:
  published_with_review_request |
  published_review_request_not_requested |
  review_request_failed | partially_applied | refused
nonclaims
committed_at
```

The owner allocates `publication_effect_id` independently before hashing.
`publication_effect_hash` covers the complete canonical body above, including
the allocated ref, the destination binding, the exact enumerated file set and
its digest, the compare-and-swap declaration, the idempotency material, and
both sub-effect outcomes; it excludes only itself. Each rule below is testable
and is pinned by a registered fixture.

- **The remote head is a compare-and-swap, and an overwrite is
  unrepresentable.** `remote_cas` declares the exact `expected_target_head`
  the effect was computed against, and `expected_base_head` must equal
  `change_set.base_revision_id`. A declared head detached from the change-set
  base is a stale compare-and-swap and is refused, never reconciled by
  overwriting. `remote_update_mode` and `stale_head_disposition` are single
  literals — `expected_head_advance_or_refuse` and `refuse_never_overwrite` —
  and the record is a closed object, so there is no field, flag, mode, or
  extension point through which a caller can request a forced overwrite of the
  remote head. Force is not disallowed by policy; it has no representation.
  When `target_ref_precondition` is `expected_head`, an absent expected head is
  itself a refusal.
- **The change set is proposal-bound and enumerated.**
  `change_set_kind` is the single literal `proposal_bound_file_set`; a
  whole-workspace or working-tree snapshot has no representable kind. Every
  published row names its `path`, `change_kind`, post-image `content_digest`,
  and the one bound `proposal_ref`, paths are unique, and `file_set_digest`
  recomputes over the bound proposal, the base revision, and the exact rows.
  `change_set.proposal_content_commitment` must equal
  `work_subject.proposal_hash`, so the set that ships is the set the proposal
  committed to. The declared file set and its digest are inside the content
  commitment.
- **The destination is bounded by an admitted binding.** `resolution` is the
  single literal `admitted_connector_binding`, and `destination_binding_ref`
  must cover `repository_ref`. The remote destination therefore resolves from
  an admitted connector/lease binding held by the estate, never from free
  caller-supplied text; a repository outside the binding is refused before any
  remote contact.
- **A source identity that names more than one revision is refused, not
  guessed.** The destination-binding and proposal families are
  content-addressed, so a logical ref is not a key: a rebinding or a revised
  proposal is a second admitted record carrying the same ref. Resolution is
  therefore BY the revision the effect pins — `destination_binding_hash` and
  `proposal_hash` — and a ref resolves only when every record carrying it pins
  the same one. When they disagree the crossing refuses by name
  (`ambiguous_destination_binding_ref`, `ambiguous_proposal_ref`), states the ref
  and how many records collide, and contacts no remote. There is deliberately no
  caller-supplied revision selector: under INV-37 caller text never chooses which
  server truth a publication compiles against, so an ambiguous identity is an
  estate-integrity defect for an operator to resolve, not a choice to delegate.
- **Publication and review request are separate receipted outcomes.** The two
  sub-effects carry their own outcome enum, their own `receipt_ref`, and their
  own `refusal_code`, and the two receipts must be distinct. An opened or
  failed review request must carry its own receipt; a failed review request is
  its own honest terminal outcome, not an omission inside a publication
  receipt. `overall_outcome` is bound to both sub-effect outcomes, and its only
  success-bearing members — `published_with_review_request` and
  `published_review_request_not_requested` — require the review request to be
  `opened` or `not_requested`. A publication that succeeded while its review
  request failed can only be stated as `review_request_failed`. Reporting
  overall success over a failed or skipped sub-effect is structurally
  impossible; it is not a reporting convention that a caller could violate.
- **Resubmission converges instead of duplicating.** `idempotency_key`
  recomputes over the bound proposal, the admitted destination binding, the
  target ref and its precondition, the expected head, and the file-set digest.
  An exact resubmission therefore carries the same key and converges; any
  changed material is a different submission and cannot claim the earlier key.
  A `converged_replay` or `refused_conflicting_replay` disposition must name
  the prior effect ref and its content commitment.
- **Nonclaims.** The record carries exactly the three declared nonclaims. It
  grants no authority: the authority is the referenced grants and lease, and
  this record only evidences that they were presented. It proves nothing about
  the remote beyond what its own receipts and evidence refs bear. It never
  asserts that any review was approved, merged, or accepted — an opened review
  request is a request, not an approval.

Registered wire contract: contract id
`schema://ioi/components/connectors-tools/scm-publication-effect/v1`
(`ioi.scm-publication-effect.v1`) with this `ScmPublicationEffect` section as
`canonical_owner_ref`. Registered negative fixtures pin each refusal above:
absent expected head, stale expected head, requested remote overwrite, unbound
destination, whole-workspace change set, a file row unattributed to the bound
proposal, a review-request failure reported as overall success, one receipt
shared across both sub-effects, a replay without a prior effect, an
idempotency key that does not recompute, and a detached content commitment.

Implementation status: implemented (single-node estate; the review-request
surface is declared and receipted but not yet bound to a host review API).
`POST /v1/hypervisor/environments/{id}/scm/publish` is owned by
`crates/node/src/bin/hypervisor_daemon_routes/scm_publication_routes.rs` and
compiles through `crates/types/src/app/scm_publication.rs`, which validates
every built effect against this contract inside the build path. The defective
route that stood in `lifecycle_routes.rs` — caller-supplied destination string,
`git add -A` whole-workspace stage, `push --force` with no expected-head
comparison, no proposal/work-run/idempotency binding, discarded persist
results, and overall success reported over a failed pull-request creation — was
REMOVED, not wrapped. In its place the destination resolves from an admitted
`scm-destination-binding` whose revision hash recomputes, the change set is the
enumerated proposal-bound file set whose declared post-images are re-digested
out of the workspace before any commit is built, the remote head advances only
under a daemon-observed expected-head compare-and-swap, both sub-effects are
separately receipted and persisted (locally, through the Agentgres
required-admission boundary, and re-read) before any outcome is reported, and
`overall_outcome` is derived from both sub-effects. Every refusal branch named
above is a named refusal dimension in the compiler and is pinned by a test
against its registered negative fixture.

Deferred: the review-request surface has no admitted host-API binding yet, so
`GitProcessScmPort::open_review_request` returns the honest
`review-request-rejected-by-remote` failure as its own receipted sub-effect
rather than a silent success; a bound review surface is the next leg.

### ScmPublicationEffect v2

`ScmPublicationEffect` v2 carries one source-control publication as **one
durable logical operation** rather than one isolated crossing. It exists to
close a single owner ruling:

> Retry-after-lost-response must be one logical SCM operation. A retry must
> never create another commit or review request merely because the first
> attempt advanced the observed head.

The `ScmPublicationOperation` identity is what makes that possible: it is
allocated and committed before any remote contact, it is derived from declared
intent only, and it survives every observation of the remote.

```text
schema_version: ioi.scm-publication-effect.v2
publication_effect_id / publication_effect_hash
execution_semantics: at_most_once_execution_plus_reconciliation
operation:
  operation_ref / operation_key
  operation_key_domain: excludes_observed_remote_state
  identity:                            # the ScmPublicationOperation identity
    work_run_ref
    proposal_ref / proposal_hash
    connector_ref / connector_revision_hash
    destination_binding_ref / destination_binding_hash
    repository_ref / target_ref / base_ref / base_revision_id
    change_set_kind: proposal_bound_file_set
    files: [ path, change_kind, content_digest, proposal_ref ]
    file_set_digest
    review_intent: requested | not_requested
    frozen_commit_metadata:
      commit_message_digest / authorship_commitment
      authored_at / commit_timestamp / metadata_digest
    intended_revision_id
authority:
  authority_grant_refs / authority_scope_refs
  capability_lease_ref / admission_receipt_ref
preparation:
  prepared_record_ref / prepared_record_hash / prepared_persisted_at
  persistence_order: prepared_persisted_before_remote_effect
  prepared_persistence_evidence_ref
attempt:
  publication_attempt_ref / attempt_number
  cas:
    mechanism: expected_head_compare_and_swap
    remote_update_mode: expected_head_advance_or_refuse
    stale_head_disposition: refuse_never_overwrite
    target_ref_precondition: expected_head | must_not_exist
    expected_target_head                 # the ONLY home of observed state
    observed_at / observation_evidence_ref
  cas_fingerprint / frozen_cas_fingerprint
  dispatch:
    prepared_record_hash
    dispatch_observation: proven_absent | proven_present | indeterminate
    dispatch_evidence_refs
recovery:
  resolution_disposition:
    first_dispatch | replayed_terminal_result |
    recovered_converged_remote | retried_frozen_cas |
    reconciliation_required
  remote_effect_invoked
  remote_convergence: matches_intended_revision | diverged | unobserved
  precondition_recheck: holds | moved | unobserved
  prior_terminal_effect_ref / prior_terminal_effect_hash
  reconciliation_code / recovery_evidence_refs
outcome:
  resulting_revision: null | { revision_id, target_head }
  proof_ref
effects:
  publication:
    outcome: published | partially_applied | refused | reconciliation_required
    receipt_ref / refusal_code / evidence_refs
  review_request:
    outcome: opened | failed | refused | not_requested |
             not_attempted | reconciliation_required
    receipt_ref / refusal_code / evidence_refs
    reconciliation:
      operation_key                      # its own, never the publication's
      resolution_disposition / remote_effect_invoked / reconciliation_code
overall_outcome
nonclaims
committed_at
```

- **The operation identity is observation-independent.** `operation_key`
  recomputes over `operation.identity` and nothing else, and `identity` is a
  closed object whose members are all declared intent: the work run, the
  proposal, the admitted destination binding, the target and base refs, the
  enumerated file set, the review intent, the frozen commit metadata, and the
  `intended_revision_id` that intent determines. There is no member for an
  observed remote head, so a head observation cannot enter the identity, and an
  implementation that folded one into the key produces a key that does not
  recompute. Two attempts separated by a lost response therefore carry the same
  operation, which is what "one logical operation" means here.
- **The expected head lives in the attempt fingerprint, not the identity.**
  `attempt.cas.expected_target_head` is the single home of observed remote
  state, and `attempt.cas_fingerprint` recomputes over the operation key, the
  target-ref precondition, that expected head, and the frozen base revision.
  The split is the whole mechanism: identity is stable across observations,
  the fingerprint is what an observation is allowed to change.
- **The compare-and-swap is frozen for the life of the operation.**
  `cas_fingerprint` must equal `frozen_cas_fingerprint`. A retry reuses the
  compare-and-swap frozen at preparation; a retry that re-observed the head and
  recomputed a different precondition is not an attempt of this operation and
  has no representation. As in v1, `remote_update_mode` and
  `stale_head_disposition` are single literals and the record is a closed
  object, so a forced overwrite has no field to travel through.
- **`Prepared` is persisted before the remote effect is invoked.**
  `persistence_order` is the single literal
  `prepared_persisted_before_remote_effect`, and a dispatch is only describable
  against the Prepared record it names: `attempt.dispatch.prepared_record_hash`
  must equal `preparation.prepared_record_hash`. A remote effect invoked before
  Prepared reached durable storage has no commitment to cite.
- **Re-entry resolves by exactly one of four routes, or it refuses.** If a
  terminal result already exists for the operation, it is replayed
  (`replayed_terminal_result`) and `remote_effect_invoked` is `false` — no
  further remote effect. If the remote already equals the intended revision,
  the original success is recovered (`recovered_converged_remote`), again with
  `remote_effect_invoked` `false` and `remote_convergence`
  `matches_intended_revision`. If dispatch is proven absent and the original
  precondition still holds, the same frozen compare-and-swap is retried
  (`retried_frozen_cas`, requiring `dispatch_observation` `proven_absent` and
  `precondition_recheck` `holds`). Otherwise the operation refuses as
  `reconciliation_required`, invokes nothing, declares a
  `reconciliation_code`, and leaves `outcome.resulting_revision` null for an
  operator to resolve.
- **A fresh child commit has no representation.** Either
  `outcome.resulting_revision` is null, or its `revision_id` and `target_head`
  both equal `operation.identity.intended_revision_id`. Because the commit
  metadata, the base revision, and the file set are all frozen inside the
  identity, the intended revision is fixed at preparation; a retry cannot
  compute a second commit onto a moved head and report it as this operation's
  result.
- **The review request reconciles independently.**
  `effects.review_request.reconciliation` carries its own `operation_key`,
  derived from the publication operation key, the frozen review intent, and the
  target ref, and required to differ from it. The review sub-effect therefore
  has its own disposition, its own `remote_effect_invoked`, its own
  reconciliation code, and its own receipt. A publication may be terminal while
  its review request is still `reconciliation_required`, stated as
  `published_review_request_reconciliation_required`; resolving one never
  resolves the other, and a review-request ambiguity cannot be absorbed into
  the publication operation.
- **This is at-most-once execution plus reconciliation. It is NOT an
  exactly-once claim.** `execution_semantics` is the single literal
  `at_most_once_execution_plus_reconciliation`, and
  `asserts_no_exactly_once_execution` is a required nonclaim on every record.
  The contract bounds the estate to invoking the remote effect at most once per
  frozen compare-and-swap and to refusing into a named reconciliation state
  whenever it cannot prove which side of a lost response it is on. It does not
  promise that the effect happened exactly once, and it does not promise that
  reconciliation succeeds. Any prose that states or implies exactly-once
  delivery for this family is wrong.
- **Nonclaims.** The record carries exactly four: it grants no authority, it
  proves nothing about the remote beyond its own receipts and evidence refs, it
  never asserts that a review was approved or accepted, and it asserts no
  exactly-once execution.

Fault coverage. Each named case is pinned by a registered fixture under
`docs/architecture/_meta/schemas/fixtures/scm-publication-effect-v2/`:

| Fault case | Behaviour required | Pinning fixture |
| --- | --- | --- |
| Lost response **before** the remote dispatch | Dispatch is proven absent and the precondition still holds, so the same frozen compare-and-swap is retried under the same operation | `positive-lost-response-before-dispatch-retry-same-frozen-cas.json`; refusal pinned by `negative-retry-recomputed-cas-onto-moved-head.json` |
| Lost response **after dispatch, before persistence** | The remote already equals the intended revision, so the original success is recovered with no further remote effect | `positive-lost-response-after-dispatch-before-persistence-recovered.json`; refusal pinned by `negative-converged-recovery-reinvoked-remote-effect.json` |
| Lost response **after persistence, before the response** | A terminal result exists, so it is replayed with no further remote effect and it names the prior terminal effect | `positive-lost-response-after-persistence-replayed-terminal.json`; refusal pinned by `negative-replay-without-prior-terminal-effect.json` |
| **Moved-head ambiguity** | Neither replay, convergence, nor a proven-absent dispatch applies, so the operation refuses as `reconciliation_required` and creates nothing | `positive-moved-head-ambiguity-reconciliation-required.json`; refusal pinned by `negative-moved-head-fresh-child-commit.json` |
| **Review-request ambiguity** | The review sub-effect reconciles on its own key while the publication stays terminal | `positive-review-request-ambiguity-independent-reconciliation.json`; refusal pinned by `negative-review-request-ambiguity-absorbed-into-publication.json` |

Observation independence itself is pinned twice: structurally by
`negative-observed-head-in-operation-identity.json`, which shows the identity
has no member an observed head could occupy, and by computation in
`negative-operation-key-bound-to-observed-head.json`, where a key derived from
the observed head no longer recomputes over the identity.

Registered wire contract: contract id
`schema://ioi/components/connectors-tools/scm-publication-effect/v2`
(`ioi.scm-publication-effect.v2`) with this `ScmPublicationEffect v2` section as
`canonical_owner_ref`. Its registry evolution fields declare
`successor_of` = the v1 contract id, `compatibility` = `breaking`,
`migration_policy` = `explicit_adapter_required`, and
`predecessor_remains_valid` = `true`; the v1 entry declares v2 as its
`successor_contract_id`. Nothing in the v1 schema, invariants, fixtures, or
nonclaims was edited.

**The v1/v2 claim boundary.** v1 and v2 are both registered and both readable.
v1 remains a valid, non-retracted contract, and its narrower nonclaim set
stands: it describes one crossing and claims nothing about retry, recovery, or
reconciliation. v2 is a breaking successor with an explicit adapter migration —
the estate **reads v1 and v2 and writes v2** once a route is compiled against
v2. A v1 record must never be read as if it carried the v2 operation identity,
the frozen compare-and-swap, or the reconciliation dispositions, and a v2
record must never be flattened into a v1 record: the migration is the adapter,
not a field-name mapping. Which contract governs a given crossing is settled by
the contract that route compiles against.

Implementation status: not implemented. Nothing in the estate builds, reads, or
persists an `ioi.scm-publication-effect.v2` record; v2 exists here as
registered schema, invariants, fixtures, and generated projections only. The
merged v1 route on
`POST /v1/hypervisor/environments/{id}/scm/publish` remains in force and
remains compiled against v1 until the v2 implementation cut lands, and no
runtime honesty claim in the v1 section above is transferred to v2. The v2
implementation cut owns the durable operation store, the Prepared write path,
the re-entry resolver, and the independent review-request reconciler.

## Risk Classes

The canonical member set and ladder order are owned by
[`../../foundations/canonical-enums.md`](../../foundations/canonical-enums.md)
(`credential_touching` is the deprecated alias of `credential_access`).
Canonical ladder excerpt:

```text
read
draft
local_write
write_reversible
external_message
commerce
funds
credential_access
policy_widening
secret_export
identity_change
system_destructive
```

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
instacart.create_cart_draft
instacart.submit_order
blender.run_python
freecad.export_step
```

## Approval Rules

```text
read: no approval by default
draft: no approval or soft approval
external_message: approval required by default
commerce: approval required
funds: approval + step-up required
secret_export: disabled by default
policy_widening: step-up + explicit approval required
```

## Non-Negotiables

1. Every tool must have a RuntimeToolContract.
2. Every effectful tool must bind to an authority grant.
3. High-risk tools require wallet.network approval.
4. Tools cannot inherit ambient connector secrets.
5. Tool output must include receipt-ready evidence.
6. Connector output used for training, evaluation, projection, routing, or
   service delivery must pass through a ConnectorMapping and, when transformed,
   a receipted DataRecipe.
7. Hypervisor MCP Gateway profiles must be scoped, expiring or revocable,
   auditable, and bound to backing contracts; they must not expose an unbounded
   master tool surface.
8. A `LocalAgentPairingSessionEnvelope` authenticates only a candidate. A local-
   agent gateway profile requires the matching admitted scope: a participant
   lease for `room_guest`, or active registration plus concrete invocation,
   Session, Automation, or WorkRun admission for a reusable private/organization
   worker. It may not inherit the pairing challenge as a durable credential.
9. Prompt-only local-agent profiles are proposal-only, visibly low assurance,
   and non-effectful; pairing alone cannot create reputation, payout, or
   marketplace publication.
10. No pairing bootstrap or gateway manifest may contain a broad org read/write
    token, raw provider credential, ambient room context, or master MCP scope.
11. Packages and reusable profiles carry immutable gateway requirements, never
    concrete subject-scoped gateway profiles, credentials, or live leases.
12. MCP tools, resources, prompts, elicitation, tasks, and Apps must normalize
    to their canonical IOI owners; no MCP-native identity replaces run,
    context, authority, state-root, or receipt truth.
13. Any declared gateway-profile change creates a successor revision; widening
    repeats admission. Lifecycle mutation of an existing revision may only
    suspend, quarantine, expire, revoke, or attach deny-only policy.
14. Network-capable RuntimeToolContracts bind destination and data-class
    allowlists. Missing declarations or a mismatched effective label fail
    before connector or tool invocation.
15. Connector/tool output enters context as provenance-bearing untrusted input
    until a declared mapping, integrity decision, and information-flow label say
    otherwise. Output-schema validation alone never grants instruction
    authority.
16. The target HTTP connector, MCP `tools/call`/`tools/list`,
    hosted-provider, guarded-browser, and Agentgres memory write/edit seams
    require actual parent labels and recompute a restrictive join; boundary
    output is untrusted/content-only and cannot mint authority. Current master
    does not yet implement those cross-plane information-flow seams.
17. MCP resources/prompts/elicitation/tasks/Apps, OutcomeRoom messages, inbound
    connector subscriptions/webhooks, full ContextCell propagation, browser
    upload/download and other interactive/computer-use actions, and remaining
    connector families are also planned. No schema/projection substrate may be
    generalized into an estate-wide IFC claim.

## ConnectorCredentialGrant

Registered contract: `schema://ioi/components/connectors-tools/connector-credential-grant/v1`.
Runtime: `/v1/hypervisor/principals/:id/lease-grants`. A principal's finite,
declared-tools-only scope over one connector's use-only lease:

- the grant never carries or exposes the sealed credential — the connector
  estate's use-only doctrine is unchanged;
- **expiry is required and enforced at the single check site** — a credential
  grant without an expiry is the standing-access defect this contract closes;
- declared tools only: nothing is granted by default, and `"*"` is a deliberate
  declaration, never a fallback;
- the granting principal is resolved server-side (INV-37);
- a regrant never silently rewrites an existing grant's tool set — revoke
  first, then grant (typed conflict otherwise);
- grant and revocation both write audit records or do not happen (grant rolls
  back on audit failure; revocation refuses before removal).
