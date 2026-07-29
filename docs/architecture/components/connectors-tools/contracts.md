# Connector and Tool Contracts

Status: canonical low-level reference.
Canonical owner: this file for RuntimeToolContract, ConnectorMapping
references, immutable MCP gateway requirements, subject-scoped Hypervisor MCP
Gateway profiles including post-pairing room-admission bindings, protocol
normalization, tool API, connector API, source-control publication effects,
risk classes, and approval rules.
Supersedes: older flattened tool capability examples in plans/specs.
Superseded by: none.
Last alignment pass: 2026-07-29.
Doctrine status: canonical
Implementation status: partial (the RuntimeToolContract owner and daemon tool catalog are live, and the registered information-flow/declassification schemas, invariants, fixtures, and generated projections provide contract substrate; production IFC propagation/enforcement, MCP resource/prompt/elicitation/task/App propagation, general inbound connector subscriptions, OutcomeRoom discussion/artifact resolution, remaining browser/computer-use families, immutable gateway requirements, `LocalAgentPairingSessionEnvelope` bindings, room-admitted local-agent gateway issuance, and the whole `ScmPublicationEffect` family remain planned)
Last implementation audit: 2026-07-29 (contract substrate; production IFC enforcement not claimed; `ScmPublicationEffect` is a target contract with no conforming runtime path)

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

### ScmPublicationEffect

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

Implementation status: planned. No current runtime path satisfies this
contract, and none of the rules above is enforced in master today. The
`handle_scm_publish` route in
`crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs`
(`POST /v1/hypervisor/environments/{id}/scm/publish`) is the route that must be
rebuilt against it: it currently accepts a caller-supplied destination string
against a host-level connector, stages the whole workspace rather than a
proposal-bound file set, advances the remote ref with no expected-head
compare-and-swap, binds no proposal, work run, or idempotency material, and
reports overall success even when the review request failed. Until that route
is rebuilt, this section is the target contract and not a description of
running behavior.

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
