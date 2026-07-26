# Bounded-System Package, Genesis, and Chain Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of bounded-autonomous-system package release, live-system genesis, constitution and amendment, deployment profile, membership, ordering/admission/finality, recovery, oracle evidence, lifecycle continuity and transition, network enrollment, and pre-AIIP local-agent pairing.
Supersedes: the same object definitions when they were carried inside the single `common-objects-and-envelopes.md` file.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: mixed (the registered contract substrate supplies schemas, invariants, adversarial fixtures, and generated Rust/TypeScript projections for the bounded-System manifest/genesis/sequence-zero-materialization/constitution/amendment/ordering/oracle/lifecycle/enrollment family; the pure genesis proposal compiler and exact wallet-authorized, statefully consumed, crash-convergent System admission with immutable local and Agentgres evidence are on master; activation, amendment/lifecycle execution, network-enrollment effects, and product surfaces are not started; local-agent pairing remains planned)
Last implementation audit: 2026-07-25

## Purpose

This module owns the shared **object shapes** listed above. It is part of the
shared-object family indexed by
[`common-objects-and-envelopes.md`](../common-objects-and-envelopes.md), which owns
the envelope base types, ID conventions, and capability/authority tiers every
module here reuses. Doctrine and lifecycle semantics for these objects are owned
by [`../governed-autonomous-systems.md`](../governed-autonomous-systems.md);
this module does not restate them.

## Package Release And Live-System Genesis

Hypervisor's primary build artifact is an Autonomous System Package.

An Autonomous System Package is the reusable developer-facing skeletal unit for
autonomous-system work. It is not an agent, connector, workflow, daemon
process, policy bundle, live system identity, or node membership. It binds
worker responsibility, GoalRunProfile and WorkflowTemplate composition,
compatible step-resolution profiles, model and tool capabilities, authority
requirements, memory/state/artifact contracts,
evaluations, profile templates and constraints, and receipt obligations into
one packageable release.

Implementation may represent the package as a strict `ManifestEnvelope` profile,
as `AutonomousSystemManifestEnvelope`, or as both. That implementation choice
must not make the package concept invisible in product, SDK, ADK, CLI/headless,
workflow, or documentation surfaces.

Package/release lifecycle and live-system lifecycle are deliberately separate:

```text
package: compose -> bind requirements -> simulate/evaluate -> package -> sign
         -> release -> promote -> deprecate or revoke

system:  instantiate/genesis -> authorize -> activate -> run -> improve
         -> recover, migrate, fork, adopt, succeed, dissolve, retire,
            archive, or decommission
```

Evaluation runs may instantiate disposable development or test systems and bind
their receipts back to a package release. The package itself never becomes
`active`, owns operational state, joins a network, fails over, succeeds, or
dissolves. `AutonomousSystemGenesisEnvelope` is the only object that binds one
selected release to a new stable `system_id`, active constitution, initial
profiles, initial state/receipt roots, and activation authority. An existing
system adopts another release through a governed upgrade; it does not create a
second genesis or change `system_id`.

Short product form:

```text
build -> bind authority -> test -> run -> inspect receipts -> package
-> promote
```

Lifecycle readiness must not collapse into one vague ready state. IOI clients
should distinguish:

| Readiness | Meaning | Blocking Scope |
| --- | --- | --- |
| Run readiness | The graph can execute now in the selected runtime profile. | Blocks Run. |
| Authority readiness | Required grants, approvals, and secret leases are available. | Blocks live effects. |
| Package readiness | The graph can become a complete Autonomous System Package. | Blocks package/publish. |
| Evaluation readiness | Eval cases, scorecards, replay expectations, and quality gates exist. | Blocks promotion. |
| Deployment readiness | The target runtime/deployment profile can run the package. | Blocks deploy. |
| Promotion readiness | The package is safe and qualified for reuse, marketplace, service, or Foundry feedback loops. | Blocks promotion. |

### Terminology Boundary

The canonical `Term | Canonical Meaning | Must Not Mean` boundary table is owned
by [`term-boundaries.md`](../term-boundaries.md). It is not restated here.

The reusable work-definition object shapes that were previously carried in this
section — `WorkflowTemplateEnvelope`, `SkillManifestEnvelope`, `SkillEntryEnvelope`,
and `ActiveSkillSetSnapshotEnvelope` — are owned by
[`reusable-work-definitions.md`](./reusable-work-definitions.md). They are reusable
definitions of work, not part of bounded-system genesis; only the package release
lifecycle above binds them into a release.

### AutonomousSystemManifestEnvelope

```yaml
AutonomousSystemManifestEnvelope:
  schema_version: ioi.autonomous-system-manifest.v1
  package_id: package://...
  manifest_id: package://.../release/...
  display_name: string
  description: string
  version: semver_or_hash
  predecessor_manifest_ref: package://.../release/... | null
  release_root: hash
  registry_status: draft | evaluable | package_ready | released | promoted | deprecated | revoked
  constitution_template_ref: artifact://... | cid://...
  required_profile_templates:
    deployment_template_ref: artifact://... | cid://...
    ordering_admission_finality_template_ref: artifact://... | cid://...
    oracle_evidence_template_refs: []
    lifecycle_continuity_template_ref: artifact://... | cid://...
    network_enrollment_constraint_ref: policy://...
  system_binding:
    allowed_use: instantiate_new | upgrade_existing | either
    compatible_constitution_constraint_ref: policy://...
    compatible_predecessor_release_roots: []
  worker:
    worker_revision_ref: worker://.../revision/...
    worker_content_hash: hash
    responsibility: string
    owner_ref: ioi://publisher/...
  typed_components:
    component_set_snapshot_ref: artifact://...
    component_set_hash: hash
    goal_run_profiles:
      - revision_ref: goal-run-profile://.../revision/...
        content_hash: hash
    workflow_templates:
      - revision_ref: workflow-template://.../revision/...
        content_hash: hash
    automation_specs:
      - revision_ref: automation://.../revision/...
        content_hash: hash
    harness_profiles:
      - revision_ref: harness-profile://.../revision/...
        content_hash: hash
    agent_harness_adapters:
      - revision_ref: agent-harness-adapter://.../revision/...
        content_hash: hash
    skill_manifests:
      - revision_ref: skill://.../revision/...
        content_hash: hash
    data_recipes:
      - revision_ref: data-recipe://.../revision/...
        content_hash: hash
    runtime_tool_contracts:
      - revision_ref: tool://.../revision/...
        content_hash: hash
    mcp_gateway_requirements:
      - revision_ref: mcp-gateway-requirement://.../revision/...
        content_hash: hash
  workflow_compatibility:
    default_workflow_template_revision_ref: workflow-template://.../revision/... | null
    default_workflow_template_content_hash: hash | null
    compatible_harness_profile_revision_refs: []
    topology_hash: string | null
  source_project:
    project_ref: optional
    repository_refs: []
    default_branch_or_ref: optional
    development_environment_recipe_ref: development-environment-recipe://.../revision/... | null
    development_environment_recipe_content_hash: hash | null
    issue_tracker_refs: []
    code_owner_refs: []
  interfaces:
    operator_console_descriptor_ref: optional
    generated_domain_app_descriptor_ref: optional
    api_contract_refs: []
    aiip_binding_requirement_refs: []
    publication_endpoint_contract_refs: []
  capabilities:
    model_capability_requirement_refs: []
    model_deployment_profile_refs: []
    capability_descriptor_refs: []
    connector_requirement_refs: []
    primitive_capabilities_required: []
  authority:
    authority_scope_requirements: []
    grant_requirements: []
    approval_profile_ref: optional
    policy_profile_ref: optional
    revocation_posture: fail_closed | pause | degrade_read_only
  runtime_profiles:
    - profile_id: profile://...
      kind: local_daemon | task_browser | local_container | hosted_daemon | cloud_vm | tee | depin | customer_vpc
      compatibility_requirement_ref: policy://... | profile://...
      cleanup_policy_ref: policy://... | null
  session_state_memory_artifacts:
    session_profile_ref: optional
    state_profile_ref: optional
    memory_profile_ref: optional
    artifact_retention_profile_ref: optional
    observation_retention_mode: summary_only | local_redacted | local_raw | encrypted_local_raw | no_persistence
  evaluation:
    eval_profile_refs: []
    benchmark_refs: []
    quality_gate_refs: []
    replay_profile_ref: optional
  promotion:
    promotion_profile_ref: optional
    release_target_refs: []
    rollout_policy_ref: optional
    rollback_policy_ref: optional
    recall_policy_ref: optional
    kill_switch_ref: optional
    marketplace_exposure_eligibility: none | internal | review_required | eligible
    foundry_lineage_refs: []
    worker_card_preview_ref: optional
  receipts:
    package_readiness_receipt_ref: optional
    release_evaluation_receipt_refs: []
  release:
    publisher_signature_ref: receipt://... | evidence://... | null
    registry_published_at: timestamp | null
```

The envelope is a package/readiness and portability contract. It must compile
to daemon/runtime, wallet.network, Agentgres, workflow, connector/tool, and
receipt contracts; it must not bypass them.

Typed component tuples preserve each component's owner and exact immutable
revision/content hash. `release_root` commits the component-set snapshot and
hash; admission rejects any tuple or snapshot mismatch. A Package distributes
immutable definitions, templates, requirements, and compatibility pins; it
does not contain a concrete MCP gateway instance, ContextLease, authority
grant, RuntimeAssignment, ActiveSkillSetSnapshot, or other admission-bound
live object. The `mcp_gateway_requirements` tuples name exact immutable
requirements that constrain later resolution. Only an admitted GoalRun, Session,
AutomationRun, worker invocation, or live System binding may reference the
resulting `mcp-gateway://...` profile. Capability descriptors and connector
requirements are semantic or dependency constraints; they are not admitted
RuntimeToolContracts, connector account bindings, credentials, or provider
invocation permission.

Each typed component lane accepts only its owner scheme:
`goal-run-profile://`, `workflow-template://`, `automation://`,
`harness-profile://`, `agent-harness-adapter://`, `skill://`,
`data-recipe://`, `tool://`, or `mcp-gateway-requirement://`, respectively.
Cross-category revision refs fail closed. Live `skill_entries` remain typed
bindings, and live gateway profiles remain `mcp-gateway://`; neither is
reclassified as a package tuple.

The release body and `release_root` are immutable. `registry_status`,
`registry_published_at`, `publisher_signature_ref`,
`package_readiness_receipt_ref`, and any registry lifecycle projection are
excluded from that root; the signature and readiness receipt bind the
already-computed root. Fixed pre-release evaluation receipts may remain
committed only when they bind the exact component-set snapshot. The manifest carries interface descriptors and contracts,
runtime compatibility requirements, and fixed release-evaluation evidence—not
live endpoints, current readiness, installation enablement, or rolling
"latest" run/evaluation receipts. Those mutable facts belong to admitted
installations or System bindings, runtime/readiness projections, catalogs, and
their individual runs and receipts.

`runtime_profiles` describe compatible execution venues for modules and
workers. They do not describe the system's member-node topology, ordering,
failover, authority distribution, or finality; those belong to the deployment
and ordering templates above and become live only through genesis or a governed
upgrade.

The portable hash profile is exact. `component_set_hash` is SHA-256 over RFC
8785 JCS for `{domain, value}`, where `domain` is
`ioi.autonomous-system-component-set-jcs-sha256.v1` and `value` is the complete
`typed_components` object with only `component_set_hash` removed.
`release_root` uses the same wrapper with domain
`ioi.autonomous-system-manifest-release-root-jcs-sha256.v1` and the complete
manifest with `release_root`, `registry_status`,
`receipts.package_readiness_receipt_ref`,
`release.publisher_signature_ref`, and
`release.registry_published_at` removed. Those are the only removals, and their
parent objects remain in the canonical value even when a removal leaves an
empty object. No implementation may substitute route-local object ordering,
remove an empty parent, or omit fixed release material from either hash.

A `draft` manifest carries no package-readiness receipt, publisher signature,
or registry publication time. `released` and `promoted` require all three.
These status conditions do not add a public-settlement requirement.

For a new-System genesis, `system_binding.allowed_use` must be
`instantiate_new` or `either`. `upgrade_existing` is valid package metadata
but cannot pass the new-System proposal compiler.

### AutonomousSystemInitialProfileBundle

```yaml
AutonomousSystemInitialProfileBundle:
  schema_version: ioi.autonomous-system-initial-profile-bundle.v1
  constitution: AutonomousSystemConstitutionEnvelope
  ordering_profile: OrderingAdmissionFinalityProfileEnvelope
  oracle_profiles:
    - OracleEvidenceProfileEnvelope
  lifecycle_profile: LifecycleContinuityProfileEnvelope
  network_enrollment: IOINetworkEnrollmentEnvelope | null
```

This is a closed canonical object with exactly the explicit keys above. Each
non-null value is the exact supplied body and must independently satisfy its
own registered contract; an empty or partial nested placeholder is not a valid
compiler input. Every body carries the same `system_id`. Ordering, lifecycle,
and a supplied enrollment bind the bundled constitution, while the enrollment
also binds the selected manifest. `oracle_profiles` preserves the supplied
array order exactly, and that order must match genesis
`initial_profile_refs.oracle_evidence_profile_refs`. The enrollment key is
always present and is explicitly `null` when no initial enrollment is supplied.

`initial_profile_bundle_root` is SHA-256 over RFC 8785 JCS for
`{domain, value}`, where `domain` is
`ioi.autonomous-system-initial-profile-bundle-jcs-sha256.v1` and `value` is
the complete bundle above. This commitment binds candidate bodies to the
proposal; it does not admit, activate, verify, or persist any profile.

### AutonomousSystemGenesisEnvelope

```yaml
AutonomousSystemGenesisEnvelope:
  schema_version: ioi.autonomous-system-genesis.v1
  genesis_id: genesis://...
  system_id: system://...
  package_id: package://...
  manifest_ref: package://.../release/...
  admitted_manifest_root: hash
  constitution_ref: constitution://...
  initial_profile_bundle_root: hash
  initial_profile_refs:
    deployment_profile_ref: deployment-profile://...
    ordering_admission_finality_profile_ref: ordering-profile://...
    oracle_evidence_profile_refs: []
    lifecycle_continuity_profile_ref: lifecycle-profile://...
    network_enrollment_ref: network-enrollment://... | null
  initial_component_bindings:
    admitted_component_set_snapshot_ref: artifact://...
    admitted_component_set_hash: hash
    goal_run_profiles:
      - revision_ref: goal-run-profile://.../revision/...
        content_hash: hash
    workflow_templates:
      - revision_ref: workflow-template://.../revision/...
        content_hash: hash
    automation_specs:
      - revision_ref: automation://.../revision/...
        content_hash: hash
    automation_installations:
      - binding_revision_ref: install://automation/.../revision/...
        binding_hash: hash
        admission_receipt_ref: receipt://...
    harness_profiles:
      - revision_ref: harness-profile://.../revision/...
        content_hash: hash
    agent_harness_adapters:
      - revision_ref: agent-harness-adapter://.../revision/...
        content_hash: hash
    skill_entries:
      - binding_revision_ref: skill-entry://.../revision/...
        binding_hash: hash
        skill_manifest_revision_ref: skill://.../revision/...
        skill_manifest_content_hash: hash
    data_recipes:
      - revision_ref: data-recipe://.../revision/...
        content_hash: hash
    runtime_tool_contracts:
      - revision_ref: tool://.../revision/...
        content_hash: hash
    mcp_gateway_profiles:
      - profile_revision_ref: mcp-gateway://.../revision/...
        profile_content_hash: hash
  instantiation:
    proposed_by: system://... | wallet://... | org://... | project://...
    decision_ref: decision://...
    authority_grant_refs: []
    conformance_receipt_refs: []
  cryptographic_origin:
    sequence: 0
    predecessor_commitment_ref: null
    genesis_operation_commitment: hash
    genesis_transition_commitment_ref: commitment://...
    initial_state_root: hash
    initial_receipt_root: hash
    admission_proof_ref: evidence://... | receipt://... | null
  activation_receipt_ref: receipt://... | null
  lifecycle_transition_refs: []
  status_source_receipt_refs: []
  created_at: timestamp
  status: proposed | authorized | activated | rejected | revoked
```

The genesis decision creates one logical system; it does not grant a node
ambient authority or activate optional network services. All live profile refs
must satisfy the new constitution's protected constraints. An enrollment ref is
valid only when its own service-selection and activation conditions pass.
Genesis `status` is a projection, not an independently mutable lifecycle. The
`initialize` and `activate` lifecycle transitions below are authoritative and
must bind this `genesis_ref`; their admitted genesis/activation receipts drive
the projected authorized/activated state.

The package may supply goal, workflow, skill, and gateway requirements, but
genesis records only definitions and bindings admitted for this System. A live
MCP gateway ref must name a separately admitted, subject- and scope-bound
profile; genesis cannot manufacture one by copying a package template.
`admitted_component_set_hash` commits every initial ref/hash tuple and must
match the admitted snapshot and activation receipt; package inclusion alone
does not activate a component. Each initially enabled AutomationSpec also
requires an exact System/owner-scoped AutomationInstallationBinding
revision/hash and its admission receipt in this set; the package remains
definition-only.

For `status: proposed`, `admission_proof_ref`, `activation_receipt_ref`,
authority-grant refs, conformance-receipt refs, lifecycle-transition refs, and
status-source receipt refs are absent or empty as typed above. `authorized`
requires an admission-proof ref, non-empty authority-grant refs, and non-empty
status-source receipt refs. `activated` requires those fields plus an activation
receipt and at least one lifecycle-transition ref. These fields make status
claims fail closed; their presence in an unverified object is not independent
proof of authorization, admission, or activation.

The pure proposal compiler accepts an immutable release plus an explicitly
supplied closed candidate input, validates every nested body against its owning
contract, recomputes the component-set hash and release root, builds and returns
the canonical initial-profile bundle/root, and derives domain-separated
operation/proposal commitments with RFC 8785 JCS. It returns bytes, roots, or a
bounded blocker report. It does not mint identity, read a current head, verify
authority, admit or activate a System, persist a record, or perform file,
daemon, network, wallet, Agentgres, clock, random, or environment effects.
Supplied evidence, grant, decision, or receipt refs are inputs to later
governance only and never prove admission or activation.
The operation commitment uses domain
`ioi.autonomous-system-genesis-operation-jcs-sha256.v1` over the proposed
genesis after inserting both `admitted_manifest_root` and
`initial_profile_bundle_root`, and before inserting either operation or
transition commitment. The final proposal root uses domain
`ioi.autonomous-system-genesis-proposal-root-jcs-sha256.v1` over the complete
compiled genesis. Both use the same `{domain, value}` JCS wrapper as the
manifest hashes.

Sequence zero is initial-only: the bundled constitution has
`predecessor_constitution_ref: null` and, while draft,
`activation_receipt_ref: null`; a supplied initial network enrollment has
`predecessor_enrollment_ref: null`. Any predecessor or constitution activation
residue blocks compilation with its own typed reason.

### AutonomousSystemSequenceZeroMaterializationEnvelope

```yaml
AutonomousSystemSequenceZeroMaterializationEnvelope:
  schema_version: ioi.autonomous-system-sequence-zero-materialization.v1
  materialization_id: system-materialization://...
  system_id: system://...
  genesis_ref: genesis://...
  genesis_admission_receipt_ref: receipt://...
  genesis_admission_record_root: hash
  genesis_admission_receipt_root: hash
  proposed_initial_state_root: hash
  proposed_initial_receipt_root: hash
  package_id: package://...
  manifest_ref: package://.../release/...
  admitted_manifest_root: hash
  constitution_ref: constitution://...
  constitution_root: hash
  profile_bundle_root: hash
  profile_materialization_root: hash
  deployment_profile_root: hash
  profile_refs:
    deployment_profile_ref: deployment-profile://.../revision/sha256:...
    ordering_admission_finality_profile_ref: ordering-profile://...
    oracle_evidence_profile_refs: []
    lifecycle_continuity_profile_ref: lifecycle-profile://...
    network_enrollment_ref: network-enrollment://... | null
  component_registry_ref: agentgres://object-set/...
  component_registry_root: hash
  component_binding_count: nonnegative_integer
  component_bindings:
    - kind: goal_run_profile | workflow_template | automation_spec | automation_installation | harness_profile | agent_harness_adapter | skill_entry | data_recipe | runtime_tool_contract | mcp_gateway_profile
      binding_ref: canonical_ref
      binding_hash: hash
      evidence_refs: []
      evidence_hashes: []
  sequence: 0
  predecessor_transition_commitment_ref: null
  operation_commitment: hash
  transition_commitment_ref: commitment://ioi/system-sequence-zero/...
  initial_state_root: hash
  initial_receipt_root: hash
  materialization_receipt_ref: receipt://...
  activation_receipt_ref: null
  created_at: timestamp
  status: materialized_pending_activation
```

This immutable M1.4 artifact freezes the exact activation candidates and the
daemon-derived sequence-zero commitment set after genesis authorization. It is
not the live `AutonomousSystemChainEnvelope`: no profile or component becomes
live merely because it appears here, and no initialize, activate, membership,
runtime, or network-enrollment effect is implied. A later authorized activation
transition must consume this exact artifact and receipt before it may populate
the live chain fields.

The daemon derives every operational root from the converged M1.3 admission and
exact normalized component/profile material. A content-addressed
`deployment_profile_ref` ending in `/revision/sha256:<hash>` contributes that
content hash directly as `deployment_profile_root`. M1.3 also admitted
unversioned refs before this requirement existed; because those predecessor
records are immutable, M1.4 preserves them through a domain-separated
compatibility commitment to the exact admitted ref. That commitment allows the
System to cross materialization without pretending a deployment-profile body
was captured, and it remains ineligible for activation until a separately
governed later transition supplies a content-addressed revision. The M1.3
genesis `initial_state_root` and `initial_receipt_root` survive only as the
explicitly named `proposed_initial_*` trace fields; they are never copied into
the operational `initial_state_root` or `initial_receipt_root`. The hash domains
are:

- `ioi.autonomous-system-component-registry-jcs-sha256.v1`;
- `ioi.autonomous-system-profile-materialization-jcs-sha256.v1`;
- `ioi.autonomous-system-legacy-deployment-profile-ref-jcs-sha256.v1`
  (compatibility only);
- `ioi.autonomous-system-sequence-zero-operation-jcs-sha256.v1`;
- `ioi.autonomous-system-sequence-zero-state-jcs-sha256.v1`;
- `ioi.autonomous-system-sequence-zero-receipt-jcs-sha256.v1`; and
- `ioi.autonomous-system-sequence-zero-transition-jcs-sha256.v1`.

The receipt-root material binds the M1.3 admission receipt/root, the deterministic
M1.4 receipt identity, operation commitment, and resulting state root. The
transition material then binds sequence zero, null predecessor, operation
commitment, M1.4 admission-proof ref, resulting state root, and receipt root.
The component registry is an exact ordered ref/hash projection, not a copy of
package contents or a grant of component execution authority.

## Governed Autonomous-System Chain Envelopes

Governed autonomous-system chains are system-local, logically scoped stateful
execution objects, not necessarily single-node objects. They are not
necessarily standalone public blockchains or IOI L1s. Their accepted
operations and receipts live in Agentgres/domain state, while IOI L1 anchors
only roots selected by an explicit enrollment and settlement profile.

The logical system is constitution-bound and may span one or many admitted
nodes. Desired topology, observed membership, ordering/finality, external-fact
policy, lifecycle continuity, and optional IOI Network enrollment are separate
objects so node count cannot silently change authority or assurance.

### AutonomousSystemConstitutionEnvelope

```yaml
AutonomousSystemConstitutionEnvelope:
  schema_version: ioi.autonomous-system-constitution.v1
  constitution_id: constitution://...
  system_id: system://...
  version: semver_or_hash
  predecessor_constitution_ref: constitution://... | null
  constitution_root: hash
  declared_purpose:
    statement: string
    ontology_refs: []
    beneficiary_or_stakeholder_refs: []
    acceptance_policy_refs: []
  normative_constraints:
    invariant_refs: []
    permitted_objective_policy_refs: []
    prohibited_objective_policy_refs: []
    permitted_ontology_action_contract_refs: []
    prohibited_effect_policy_refs: []
  agency_boundary:
    authority_ceiling_scope_refs: []
    delegable_scope_refs: []
    non_delegable_scope_refs: []
    resource_and_budget_ceiling_policy_refs: []
    time_and_duration_ceiling_policy_refs: []
    data_and_privacy_ceiling_policy_refs: []
    effect_and_externality_ceiling_policy_refs: []
    egress_policy_ref: policy://...
    node_expansion: governed_membership_only
    code_propagation: admitted_deployment_only
    self_authority_widening: forbidden
  governance:
    governance_owner_refs: []
    accountable_principal_refs: []
    affected_party_policy_ref: policy://...
    ordinary_upgrade_policy_ref: policy://...
    amendment_mode: immutable | external_governance_only
    amendment_decision_profile_ref: policy://... | null
    protected_clause_refs: []
    protected_field_paths: []
    agent_may_propose_amendment: boolean
    agent_may_commit_amendment: false
    emergency_pause_authority_refs: []
    revocation_authority_refs: []
  protected_profile_governance:
    improvement_governance_profile_ref:
      improvement-governance-profile://.../revision/... | null
    improvement_governance_profile_change_decision_profile_ref: policy://... | null
    deployment_constraint_ref: policy://...
    deployment_change_decision_profile_ref: policy://...
    ordering_admission_finality_constraint_ref: policy://...
    ordering_profile_change_decision_profile_ref: policy://...
    oracle_evidence_constraint_ref: policy://...
    oracle_profile_change_decision_profile_ref: policy://...
    lifecycle_continuity_constraint_ref: policy://...
    lifecycle_profile_change_decision_profile_ref: policy://...
    network_enrollment_constraint_ref: policy://...
    network_enrollment_change_decision_profile_ref: policy://...
  shutdown:
    kill_switch_ref: optional
    decommission_policy_ref: policy://...
    minimum_archive_policy_ref: policy://...
  activation_receipt_ref: receipt://... | null
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
  status: draft | active | superseded | revoked
```

Purpose prose is explanatory; the referenced invariants, policies, ontology
action contracts, scopes, ceilings, and decision rules are normative. Ordinary
upgrades cannot amend protected purpose, authority ceilings, amendment gates,
improvement governance, ordering/finality, oracle, lifecycle, or shutdown
boundaries. A bounded system
can still pursue a harmful purpose: the constitution makes its declared and
enforceable bounds auditable; it does not prove benevolence.

The constitution protects constraints and decision paths, not one forever-
current mutable profile ID. Its improvement-governance profile constrains
campaign admission and promotion but does not grant a campaign authority or
declare its evidence valid. Package templates are deployment candidates;
genesis `initial_profile_refs` remain candidates while genesis is proposed or
authorized and become the first admitted live refs only when activation commits.
The live
`AutonomousSystemChainEnvelope` fields are the currently
admitted refs. Activation or later profile change must prove that each live ref
satisfies the constitutional constraint and was admitted through the matching
decision profile. Changing a live ref does not amend the constitution; changing
its constraint or decision path does.

A null improvement-governance profile disables ImprovementCampaign admission
and unattended target-generation for that System; it does not disable ordinary
owner-governed one-shot UpgradeProposals. Enabling the profile follows the
constitution's protected amendment/change path rather than an implicit default.

A `draft` constitution has neither an activation receipt nor a public
commitment. An `active` constitution requires its activation receipt. This does
not require public settlement.

### AutonomousSystemConstitutionAmendmentEnvelope

```yaml
AutonomousSystemConstitutionAmendmentEnvelope:
  schema_version: ioi.autonomous-system-constitution-amendment.v1
  amendment_id: constitution-amendment://...
  system_id: system://...
  predecessor_constitution_ref: constitution://...
  predecessor_constitution_root: hash
  proposed_successor_constitution_ref: constitution://...
  proposed_successor_constitution_root: hash
  changed_field_paths: []
  protected_field_paths: []
  governing_decision_profile_ref: policy://...
  proposal_ref: proposal://...
  evidence_refs: []
  authority_requirement_refs: []
  proposed_by_ref: user://... | wallet://... | org://... | project://... | system://... | governance://...
  decision_ref: decision://... | null
  status: proposed | evidence_pending | approved | rejected
```

This envelope is immutable proposal and decision evidence. It binds the exact
predecessor and proposed successor constitution identities and roots, declares
every changed path and every protected path touched by the proposal, and names
the governing decision profile, evidence, and authority requirements. A System
may propose an amendment only when its active constitution permits that
proposal posture; the proposal cannot satisfy its own authority requirements.

`approved` means only that the referenced external-governance decision approved this exact
proposal. It does not mutate, supersede, admit, or activate either constitution,
and it grants no authority. A separately verified constitutional transition
must bind the same roots and decision under the active predecessor's external
governance path before any successor can become live. Amendment execution,
admission, activation, and transition effects are not implemented by this
contract.

`governance.protected_field_paths` is the machine-readable RFC 6901 projection
of the human/governance-facing `protected_clause_refs`. Amendment execution
derives its protected-path floor from this committed constitution field and
requires the declaration to restate the exact same set; caller-supplied paths
never define what is protected. New constitution writers MUST populate this
field. It remains optional only when reading historical v1 constitution bytes;
a legacy constitution that omits it is ineligible for amendment execution until
an owner-authorized compatibility migration supplies a protected-path mapping.

### AutonomousSystemConstitutionAmendmentApprovalDecisionEnvelope

```yaml
AutonomousSystemConstitutionAmendmentApprovalDecisionEnvelope:
  schema_version: ioi.autonomous-system-constitution-amendment-approval-decision.v1
  decision_ref: decision://...
  decision_root: sha256:...
  amendment_ref: constitution-amendment://...
  amendment_root: sha256:...
  proposal_ref: proposal://...
  system_id: system://...
  governing_decision_profile_ref: policy://...
  predecessor_constitution_root: sha256:...
  successor_constitution_root: sha256:...
  changed_field_paths_commitment: sha256:...
  evidence_refs: []
  authority_requirement_refs: []
  outcome: approved
  decided_at: timestamp
```

This is the external-governance decision that makes an amendment declaration
eligible for execution. Its recomputable root binds the exact proposal,
the declaration's exact `amendment_root`, predecessor and successor roots,
canonical changed-path commitment, governing
decision profile, evidence, and authority requirements. It is not the later
wallet-backed execution decision and grants no chain-write authority by itself.
The daemon accepts it only with durable authority evidence from the active
constitution's single external governance owner under the
committed decision profile. Execution requires both this approval and a
distinct exact-scope authority decision over the resulting chain effect.

### AutonomousSystemChainWriterReservationEnvelope

```yaml
AutonomousSystemChainWriterReservationEnvelope:
  schema_version: ioi.autonomous-system-chain-writer-reservation.v1
  reservation_ref: chain-writer-reservation://sha256:...
  system_id: system://...
  sequence: integer >= 3
  predecessor_chain_root: sha256:...
  writer_plan_hash: sha256:...
  operation_ref: proposal://...
  operation_root: sha256:...
  operation: protected_lifecycle_op | amend_constitution
```

This expected-absent Agentgres record reserves the one writer permitted to
advance a predecessor chain root. It is admitted after a sealed intent exists
but before any wallet grant is consumed. An independent writer that loses the
reservation therefore removes its unconsumed local intent and cannot strand a
pending mutation. The winning reservation remains immutable recovery evidence;
the later successor claim binds the final materialized chain root.

### AutonomousSystemChainSuccessorClaimEnvelope

```yaml
AutonomousSystemChainSuccessorClaimEnvelope:
  schema_version: ioi.autonomous-system-chain-successor-claim.v1
  claim_ref: chain-successor-claim://sha256:...
  system_id: system://...
  sequence: integer >= 3
  predecessor_chain_root: sha256:...
  successor_chain_root: sha256:...
  operation_ref: proposal://...
  operation_root: sha256:...
  operation: protected_lifecycle_op | amend_constitution
  committed_at: timestamp
```

The predecessor chain root is the compare-and-set key. Local durable storage
and required Agentgres admission are both append-only and expected-absent at
that key. An exact replay is idempotent; any different successor, operation,
or commitment loses the claim. The claim is admitted before successor graph
visibility, so independent daemon processes cannot extend one predecessor
into sibling chain heads.

### AutonomousSystemAmendmentTransitionEnvelope

`AutonomousSystemAmendmentTransitionEnvelope` has the closed
`LifecycleTransitionEnvelope` field shape, with
`schema_version: ioi.autonomous-system-amendment-transition.v1` and
`transition_kind: amend_constitution`. Its predecessor and resulting state
roots must differ only through constitution and active-profile-set bindings;
operational status remains unchanged. The artifact root domain is
`ioi.autonomous-system-amendment-transition-jcs-sha256.v1`.

### AutonomousSystemAmendmentReceiptEnvelope

`AutonomousSystemAmendmentReceiptEnvelope` has the closed lifecycle receipt
shape with `schema_version: ioi.autonomous-system-amendment-receipt.v1`,
`op: amend_constitution`, exact amendment scope, and
`assurance_posture: constitutional_amendment_committed`. Its bound facts
include the declaration root, external approval-decision root, predecessor and
successor constitution roots, canonical changed-path commitment, transition
and state roots, predecessor chain root, and successor profile-set binding.
The artifact root domain is
`ioi.autonomous-system-amendment-receipt-artifact-jcs-sha256.v1`.

### ImprovementGovernanceProfileEnvelope

An accountable owner binds one immutable, owner-qualified policy profile for
bounded improvement. For a System, its constitution protects the selected
profile and change path. A user, project, or organization may bind the same
profile family for a non-System research Campaign, but that does not create a
System, constitution, or bounded-DAS conformance claim. The profile controls
whether the owner scope may admit Campaign work; it is not a campaign,
evaluator, authority grant, or promotion decision.

```yaml
ImprovementGovernanceProfileEnvelope:
  schema_version: ioi.improvement-governance-profile.v1
  improvement_governance_profile_id: improvement-governance-profile://...
  revision_ref: improvement-governance-profile://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref:
    improvement-governance-profile://.../revision/... | null
  content_hash: hash
  owner_ref: user://... | org://... | project://... | system://...
  system_id: system://... | null
  mutable_target_allowlist_refs: []
  protected_target_refs: []
  protected_target_change_decision_profile_refs: []
  max_target_improvement_order: nonnegative_integer
  max_active_nested_campaign_depth: positive_integer
  max_unattended_target_generations: nonnegative_integer
  ancestor_reservation_policy_refs:
    resource_budget: policy://...
    statistical_risk_budget: policy://...
    evaluation_exposure_budget: policy://...
  campaign_admission_policy_ref: policy://...
  campaign_stop_policy_ref: policy://...
  evaluator_firewall_policy_ref: policy://...
  evaluator_independence_policy_ref: policy://...
  promotion_authority_policy_ref: policy://...
  irreversible_effect_recovery_policy_ref: policy://...
  registry_lifecycle_ref: agentgres://object/... | decision://... | null
  registry_status: draft | active | superseded | revoked
```

The revision body and `content_hash` are immutable; registry lifecycle and
status are projections outside that hash. Descendants reserve disjoint
resource, statistical-risk, and evaluation-exposure allowances from their
ancestors. Naming a higher target order or creating another GoalRun never
duplicates or resets those allowances. For a System-scoped profile,
replacement follows the constitution's protected change path; otherwise it
follows the owner scope's declared governance path. Either applies only to
newly admitted work unless an explicit pause, quarantine, or migration decision
says otherwise.

### AutonomousSystemDeploymentProfileEnvelope

```yaml
AutonomousSystemDeploymentProfileEnvelope:
  schema_version: ioi.autonomous-system-deployment-profile.v1
  deployment_profile_id: deployment-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  manifest_ref: package://.../release/...
  version: semver_or_hash
  environment_class: development | test | staging | production | recovery
  environment_and_custody_profile_ref: policy://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  role_requirements:
    - role: autonomous_system_node_role
      minimum_ready_nodes: nonnegative_integer
      maximum_active_nodes: positive_integer | null
      placement_policy_ref: policy://...
      failure_independence_policy_ref: policy://... | null
      colocation_allowed: boolean
  state_distribution:
    operation_log_replication_factor: positive_integer
    projection_replication_factor: positive_integer
    artifact_replication_factor: positive_integer
    minimum_ack_durability: buffered | device_flush | replicated_same_host | quorum_replicated
    consistency_and_read_watermark_policy_ref: policy://...
    checkpoint_policy_ref: policy://...
    catchup_policy_ref: policy://...
  scaling:
    mode: manual | policy_automated
    scaling_policy_ref: policy://...
    eligible_automatic_roles:
      - projection_replica
      - execution_worker
      - artifact_replica
    authority_role_changes: governed_only
    rebalance_policy_ref: policy://...
  membership_policy_ref: policy://...
  failover_profile_ref: failover-profile://...
  partition_and_degraded_mode_policy_ref: policy://...
  restore_policy_ref: policy://...
  rollout_policy_ref: policy://...
  rollback_policy_ref: policy://...
  drain_and_removal_policy_ref: policy://...
  receipt_obligations: []
  status: draft | active | superseded | revoked
```

This is desired topology. Live node state is carried only by observed
membership records. Authority-bearing roles are never automatically scaled.

### AutonomousSystemDeploymentProfileRevisionEnvelope

```yaml
AutonomousSystemDeploymentProfileRevisionEnvelope:
  schema_version: ioi.autonomous-system-deployment-profile-revision.v1
  deployment_profile_ref: deployment-profile://.../revision/sha256:...
  deployment_profile_root: sha256:...
  profile: AutonomousSystemDeploymentProfileEnvelope
```

The revision is an immutable candidate, not an activation. Its reference is
namespaced beneath `profile.deployment_profile_id`; its suffix and
`deployment_profile_root` equal the domain-separated JCS root of the exact
draft profile body. Activation loads this projection and binds its
`system_id`, `constitution_ref`, `manifest_ref`, and
`ordering_admission_finality_profile_ref` to the converged M1.4 source. The
legacy unversioned deployment-profile compatibility commitment remains valid
M1.4 history but cannot authorize activation or stand in for profile content.

### AutonomousSystemNodeMembershipEnvelope

```yaml
AutonomousSystemNodeMembershipEnvelope:
  schema_version: ioi.autonomous-system-node-membership.v1
  node_membership_id: node-membership://...
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  node_id: node://...
  node_owner_ref: wallet://... | org://... | project://...
  membership_epoch: nonnegative_integer
  membership_lease_ref: lease://...
  role_assignments:
    - role: autonomous_system_node_role
      role_scope_refs: []
      authority_grant_refs: []
      role_lease_ref: lease://... | null
      admitted_epoch: nonnegative_integer
      valid_from: timestamp
      expires_at: timestamp | null
  failure_domain_refs: []
  failure_independence_evidence_refs: []
  node_attestation_refs: []
  conformance_profile_refs: []
  admission:
    proposal_ref: proposal://...
    decision_ref: decision://...
    admitted_constitution_root: hash
    admitted_manifest_root: hash
    admitted_deployment_profile_root: hash
  synchronization:
    checkpoint_ref: checkpoint://... | null
    operation_offset: nonnegative_integer
    verified_state_root: hash | null
    catchup_receipt_ref: receipt://... | null
    verified_at: timestamp | null
  writer_fencing:
    writer_epoch: nonnegative_integer | null
    writer_epoch_transition_ref: writer-transition://... | null
    writer_epoch_transition_hash: hash | null
    writer_lease_ref: lease://... | null
    promotion_receipt_ref: receipt://... | null
  observation:
    readiness: unknown | syncing | ready | degraded | unreachable | failed_closed
    health_observation_ref: agentgres://... | event://... | null
    heartbeat_ref: event://... | receipt://... | null
    readiness_evidence_refs: []
    last_heartbeat_at: timestamp | null
    last_observed_at: timestamp
    observation_expires_at: timestamp
  status: candidate | attesting | admitted | active | draining | suspended | revoked | left | failed_closed
```

Joining authenticates and admits a node; it does not inherently assign an
authority-bearing role. `hot_standby` cannot admit writes until a governed
epoch promotion fences the previous writer.

Membership lifecycle and observed readiness are separate. An unexpired
membership or role lease does not prove a healthy node; stale heartbeat,
readiness, or root evidence makes the observation `unknown`, `degraded`, or
`unreachable` under policy and cannot satisfy promotion or availability claims.

### AutonomousSystemFailoverProfileEnvelope

```yaml
AutonomousSystemFailoverProfileEnvelope:
  schema_version: ioi.autonomous-system-failover-profile.v1
  failover_profile_id: failover-profile://...
  system_id: system://...
  version: semver_or_hash
  response_authorization_mode: manual_governance | preauthorized_policy | protocol_native
  recovery_mechanism: unavailable_fail_closed | single_writer_restore | single_writer_promotion | ordering_profile_native
  failure_condition_policy_refs: []
  failure_detection_policy_ref: policy://...
  minimum_independent_witnesses: nonnegative_integer
  evidence_freshness_policy_ref: policy://...
  ambiguous_partition_response: fail_closed
  deployment_timing_assumptions:
    evidence_mode: bounded_clock_partial_synchrony | external_witness
    clock_or_witness_profile_ref: policy://... | witness-profile://...
    temporal_verification_profile_ref: policy://...
    maximum_clock_skew_or_uncertainty_ms: nonnegative_integer
    heartbeat_interval_ms: positive_integer
    heartbeat_evidence_expires_after_ms: positive_integer
    writer_lease_ttl_ms: positive_integer
    writer_lease_renewal_margin_ms: positive_integer
    maximum_effect_lease_ttl_ms: positive_integer
    maximum_revocation_propagation_ms: nonnegative_integer
    promotion_waitout_policy_ref: policy://...
  durable_continuity_cas:
    mechanism: witness_quorum_cas | wallet_epoch_authority | external_coordination_service
    substrate_ref: agentgres://... | wallet://... | service://...
    head_namespace: string
    cas_proof_schema_ref: schema://...
    minimum_independent_witnesses: nonnegative_integer
    unavailable_or_ambiguous_response: fail_closed
  single_writer_restore: object | null
    recovery_target: same_admitted_node | governed_replacement
    restore_policy_ref: policy://...
    required_checkpoint_and_log_proof_schema_ref: schema://...
    require_verified_resulting_state_root: true
    require_writer_epoch_increment: boolean
    require_displaced_writer_fencing: boolean
    required_authority_refs: []
  single_writer_promotion: object | null
    candidate_role: hot_standby
    required_authority_refs: []
    minimum_durability: buffered | device_flush | replicated_same_host | quorum_replicated
    require_latest_verified_state_root: true
    require_catchup_receipt: true
    require_writer_epoch_increment: true
    require_old_writer_fencing: true
    promotion_policy_ref: policy://...
  ordering_profile_recovery: object | null
    recovery_policy_ref: policy://... | null
    view_or_round_change_rule_ref: policy://... | null
    membership_transition_rule_ref: policy://... | null
    external_finality_recovery_rule_ref: policy://... | null
    recovery_proof_schema_ref: schema://...
    resulting_finality_proof_schema_ref: schema://...
  continuity_targets:
    target_recovery_point_ref: policy://...
    target_recovery_time_ref: policy://...
    work_lease_reconciliation_policy_ref: policy://...
    rebalance_policy_ref: policy://...
  receipt_obligations: []
  status: draft | active | superseded | revoked
```

`response_authorization_mode` answers who or what may initiate/authorize the
response; `recovery_mechanism` answers how the active ordering profile recovers.
They are independent axes. A `single_authority` system may select
`unavailable_fail_closed`, receipted `single_writer_restore`, or
`single_writer_promotion`; the first requires every recovery object to be null,
the second requires only its restore object, and the third requires only its
promotion object. A `replicated_single_authority` system normally selects
restore or promotion. Replacement restore and promotion require a new writer
epoch and fencing; a same-admitted-node restart follows the active restore
policy and must prove checkpoint/log continuity and its resulting state root.
Policy automation may automate detection, proposal, and pre-authorized
recovery; it never creates authority silently. For threshold, BFT, or external-finality profiles,
the mechanism is `ordering_profile_native`, the single-writer object is null,
and recovery binds the applicable threshold, round/view, membership, or
external-finality proof rather than inventing a hot-standby writer epoch.
`protocol_native` authorization is valid only when the active ordering profile
defines it. An ambiguous partition fails closed. This system writer/state
object is distinct from provider-placement `FailoverPlan` in
decentralized.cloud.

Timing is a declared deployment assumption, not a generic clock service. The
renewal margin must be shorter than the writer-lease TTL, heartbeat evidence
must expire after its declared interval, and a preauthorized promotion requires
either bounded-clock partial-synchrony evidence or the named external witness.
The referenced `TemporalVerificationProfile` qualifies the exact absolute-time,
elapsed-duration, status-as-of, and continuity-floor claims. A named source,
point timestamp, owner epoch, or healthy observation does not establish those
claims by implication, and the resulting `TemporalValidityEvaluation` does not
authorize promotion.
The successor writer cannot emit consequential effects until every affected
resource fence has advanced, or until the declared wait-out covers the latest
possible displaced-writer/effect lease, revocation propagation, and clock
uncertainty. Incrementing an integer without a successful durable continuity
CAS does not create a writer fence.

### AutonomousSystemWriterEpochTransitionEnvelope

One immutable transition advances a single System's active writer. This is a
logical-System authority and continuity object. It is distinct from the
Agentgres mux/storage-writer epoch used to fence replicas of one storage log.

```yaml
AutonomousSystemWriterEpochTransitionEnvelope:
  schema_version: ioi.autonomous-system-writer-epoch-transition.v1
  writer_epoch_transition_id: writer-transition://...
  writer_epoch_transition_hash: hash
  transition_kind: genesis | same_node_restore | replacement_restore | promotion
  system_id: system://...
  deployment_profile_ref: deployment-profile://...
  deployment_profile_root: hash
  failover_profile_ref: failover-profile://...
  failover_profile_root: hash
  ordering_profile_ref: ordering-profile://...
  ordering_profile_root: hash
  predecessor_transition_ref: writer-transition://... | null
  predecessor_transition_hash: hash | null
  expected_membership_root: hash | null
  resulting_membership_root: hash
  prior_writer:
    node_membership_ref: node-membership://... | null
    node_id: node://... | null
    membership_epoch: nonnegative_integer | null
    writer_epoch: nonnegative_integer
  successor_writer:
    node_membership_ref: node-membership://...
    node_id: node://...
    membership_epoch: nonnegative_integer
    writer_epoch: positive_integer
    writer_lease_ref: lease://...
  continuity:
    verified_state_root: hash
    checkpoint_ref: checkpoint://... | null
    operation_offset: nonnegative_integer
    catchup_receipt_ref: receipt://...
    state_root_verification_ref: verification://...
  continuity_cas:
    mechanism: witness_quorum_cas | wallet_epoch_authority | external_coordination_service
    substrate_ref: agentgres://... | wallet://... | service://...
    expected_head: hash | null
    resulting_head: hash
    proof_ref: evidence://... | receipt://...
  authority:
    authority_grant_refs: []
    authority_revocation_snapshot_ref: snapshot://...
    authority_revocation_epoch: nonnegative_integer
  displaced_writer_fencing:
    writer_fence_receipt_refs: []
    effect_lease_fence_receipt_refs: []
    effects_admissible_not_before: timestamp
  timing_evidence:
    temporal_verification_profile_ref: policy://...
    temporal_validity_evaluation_ref: evidence://... | receipt://...
    temporal_validity_evaluation_hash: hash
    observed_at: timestamp
    expires_at: timestamp
    displaced_writer_leases_expire_at: timestamp
    revocation_propagation_complete_at: timestamp
    maximum_clock_skew_or_uncertainty_ms: nonnegative_integer
    witness_evidence_refs: []
  resource_fences:
    - resource_id: string
      allowed_effect_kinds: []
      minimum_read_consistency:
        cached_projection | projection_consistent | snapshot_consistent |
        state_root_consistent | linearized_domain | serializable_domain
      read_watermark: string
  lost_suffix_record_ref: lost-suffix://... | null
  admission_receipt_ref: receipt://...
  committed_at: timestamp
```

Except at genesis, the new writer epoch is exactly the active epoch plus one;
predecessor ref/hash, profile refs/roots, membership roots, prior writer, and
CAS expected head must equal durable active truth. Catch-up, verified state
root, a nonempty unique set of active authority-grant refs, revocation evidence,
displaced-writer fencing or safe wait-out, and every declared resource fence
are admission requirements. Timing evidence must satisfy
`observed_at <= committed_at <= expires_at`; effect activation must cover the
maximum displaced lease, revocation propagation, and declared clock/witness
uncertainty without exceeding evidence expiry. Those scalar comparisons are
accepted only when the bound `TemporalValidityEvaluation` establishes the
required interval, status-as-of, and continuity claims under the exact profile;
an overlapping or unavailable result fails closed. The CAS
resulting head binds the exact immutable transition: the content commitment is
computed over every field except `writer_epoch_transition_hash` and
`continuity_cas.resulting_head`, and both excluded fields must then equal that
commitment. A stale, skipped, foreign, or merely caller-asserted epoch cannot
advance the active projection.

Immutable transition truth is persisted before the rebuildable active-fence
projection. Startup and authoritative loads replay each System chain at every
transition's commit-time validation horizon, reject duplicate genesis roots,
forks, gaps, predecessor/hash mismatches, commit-time regression, tampered
content commitments, and orphan active files, then atomically restore the exact
latest projection. Authority-record filenames derive from a collision-resistant
commitment to the full canonical ref; lossy sanitized refs are not identity.

### LostSuffixRecordEnvelope

Recovery records what the new authoritative history excludes. It never hides
or silently merges an old writer's suffix on rejoin.

```yaml
LostSuffixRecordEnvelope:
  schema_version: ioi.lost-suffix-record.v1
  lost_suffix_record_id: lost-suffix://...
  system_id: system://...
  writer_epoch_transition_ref: writer-transition://...
  prior_writer_epoch: nonnegative_integer
  last_common:
    operation_offset: nonnegative_integer
    state_root: hash
  authoritative_head:
    operation_offset: nonnegative_integer
    state_root: hash
  excluded_suffix:
    first_offset: nonnegative_integer
    last_offset: nonnegative_integer
    commitment_refs: []
    custody_artifact_refs: []
  classification:
    lost_unacknowledged | orphaned_acknowledged_below_required_durability | ambiguous
  reconciliation_policy_ref: policy://...
  disposition: retained_for_forensics | compensating_transition_required | adjudication_required | destroyed_under_policy
  disposition_receipt_refs: []
  status: open | reconciled | adjudicated | closed
  recorded_at: timestamp
```

### ConsequentialEffectFenceContext

`ConsequentialEffectFenceContext` is generated and embedded at a policy
enforcement point. It is not a grant, lease, top-level runtime object, or source
of owner identity:

```yaml
ConsequentialEffectFenceContext:
  schema_version: ioi.consequential-effect-fence-context.v1
  system_id: system://...
  executing_node_id: node://...
  resource_id: string
  effect_kind: string
  exact_payload_hash: hash
  deployment_profile_root: hash
  node_membership_epoch: nonnegative_integer
  node_membership_root: hash
  writer_epoch_transition_ref: writer-transition://...
  writer_epoch_transition_hash: hash
  writer_epoch: positive_integer
  writer_lease_expires_at: timestamp
  authority_grant_ref: grant://...
  authority_revocation_snapshot_ref: snapshot://...
  authority_revocation_epoch: nonnegative_integer
  temporal_verification_profile_ref: policy://...
  temporal_validity_evaluation_ref: evidence://... | receipt://...
  temporal_validity_evaluation_hash: hash
  read_consistency:
    cached_projection | projection_consistent | snapshot_consistent |
    state_root_consistent | linearized_domain | serializable_domain
  read_watermark: string
  read_state_root: hash
  idempotency_key: string
  evaluated_at: timestamp
  expires_at: timestamp
```

The effect owner record supplies `system_id`; trusted daemon startup/config
supplies `executing_node_id`; and the PEP supplies its own exact resource and
effect identities and hashes the exact effect payload. Caller-authored fence
contexts are refused. The PEP then requires the executing node to equal the
active writer and requires the current tuple `(system_id, writer_epoch_transition_hash,
authority_revocation_epoch)`, exact membership/deployment roots, an unexpired
writer/timing posture, and the resource's declared read consistency,
watermark, and state root. Caller omission never converts a System-scoped
effect into an unscoped effect. Any stale or mismatched field refuses before
the consequential invoker is called.
The bound temporal profile/evaluation must establish every required expiry,
status-as-of, and continuity claim, but it is not the fence. The resource still
compares its owner-derived active generation and context immediately before
invocation; an otherwise fresh former writer is refused after a higher fence.
Observed read evidence supplies the context's consistency, watermark, and state
root; a PEP may not copy the resource fence's required values and present them
as observations. If the executing path cannot derive those facts from durable
owner/projection state, the System-scoped effect is unavailable.

### OrderingFinalityRecoveryEnvelope

The failover profile contains immutable recovery rules and proof schemas. A
specific threshold, BFT, membership-reconfiguration, or external-finality
recovery is a separate admitted transition:

```yaml
OrderingFinalityRecoveryEnvelope:
  schema_version: ioi.ordering-finality-recovery.v1
  ordering_recovery_id: ordering-recovery://...
  system_id: system://...
  failover_profile_ref: failover-profile://...
  ordering_admission_finality_profile_ref: ordering-profile://...
  recovery_class: threshold_view_or_round | bft_view_or_round | membership_reconfiguration | external_finality_rebind
  predecessor:
    sequence: nonnegative_integer
    transition_commitment_ref: commitment://...
    state_root: hash
    membership_root: hash
    view_or_round: nonnegative_integer | null
    external_finality_ref: evidence://... | null
  trigger_evidence_refs: []
  governing_decision_ref: decision://... | null
  authority_grant_refs: []
  transition:
    proposed_view_or_round: nonnegative_integer | null
    membership_transition_ref: transition://... | decision://... | null
    expected_membership_root: hash
    resulting_membership_root: hash
    threshold_or_consensus_proof_refs: []
    external_finality_recovery_ref: evidence://... | null
    recovery_proof_ref: evidence://...
  result:
    sequence: nonnegative_integer
    transition_commitment_ref: commitment://...
    state_root: hash
    finality_proof_ref: evidence://...
    receipt_ref: receipt://... | null
  status: proposed | evidence_pending | authorized | admitted | committed | rejected | failed_closed
```

This object never invents authority. Its predecessor fields are compare-and-
swap inputs; its proof must satisfy the active profile and its resulting
commitment must preserve the cryptographic chain. Single-writer promotion uses
the writer-promotion/fencing contract instead of this envelope.

### OrderingAdmissionFinalityProfileEnvelope

```yaml
OrderingAdmissionFinalityProfileEnvelope:
  schema_version: ioi.ordering-admission-finality-profile.v1
  ordering_profile_id: ordering-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  version: semver_or_hash
  profile: single_authority | replicated_single_authority | threshold_authority | bft_consensus | external_chain_finality
  authority_distribution:
    posture: single_principal | declared_multi_principal | external_network
    principal_refs: []
    independence_evidence_refs: []
  ordering:
    rule_ref: policy://...
    member_node_membership_refs: []
    writer_epoch_required: boolean
    fencing_required: boolean
    leader_or_sequencer_selection_ref: policy://... | null
    conflict_rule_ref: policy://...
  admission:
    deterministic_transition_function_ref: artifact://... | cid://...
    schema_root: hash
    policy_root: hash
    authority_rule_ref: policy://...
    threshold:
      required: nonnegative_integer
      eligible: nonnegative_integer
    require_expected_predecessor_root: true
    receipt_obligations: []
  cryptographic_continuity:
    hash_and_signature_suite_ref: schema://...
    sequence_rule_ref: policy://...
    require_monotonic_sequence: true
    require_expected_predecessor_commitment: true
    operation_or_batch_commitment_schema_ref: schema://...
    admission_proof_schema_ref: schema://...
    require_resulting_state_root: true
    require_receipt_root: true
    checkpoint_and_compaction_policy_ref: policy://...
  finality:
    scope: local_operational | cross_domain | public_economic
    rule_ref: policy://...
    proof_schema_ref: schema://...
    rollback_posture: recoverable_before_final | compensation_only_after_final | irreversible_after_final
    external_network_ref: network://... | chain://... | domain://sovereign-settlement/... | null
    external_contract_ref: optional
    external_confirmation_policy_ref: policy://... | null
  fault_model_ref: policy://...
  liveness_policy_ref: policy://...
  membership_and_profile_change_policy_ref: policy://...
  conformance_receipt_refs: []
  status: draft | active | superseded | revoked
```

`single_authority` and `replicated_single_authority` have exactly one active
`admission_writer`. Replication, node count, and durability quorum never upgrade
authority distribution or public-finality claims. `threshold_authority` is
k-of-n admission, not BFT consensus unless a named protocol also solves
ordering and its declared fault model. `bft_consensus` names the protocol,
membership rule, fault assumptions, and finality proof.
`external_chain_finality` names the external network, contract, proof, and
confirmation rule. Local operational finality must never be marketed as public
or economic finality.

An `external_network_ref` uses `network://` or `chain://` by default. A
`domain://sovereign-settlement/...` ref is valid only when the external finality
source is explicitly modeled as a sovereign settlement domain; an ordinary
application domain is not a chain-finality proof.

The `cryptographic_continuity` block is the minimum for the **intelligent
blockchain** classification under every ordering profile, including
single-authority/PoA-1. Each admitted operation or batch binds a monotonic
sequence, expected predecessor commitment, operation/batch commitment,
admission signature or proof, resulting state root, and receipt root. A bounded
DAS without that verifiable root/commitment chain is a bounded autonomous
application or institution, not an intelligent blockchain. Consensus and a
token remain optional.

A `draft` ordering profile has no conformance receipts. An `active` ordering
profile requires at least one conformance receipt; changing the status string
alone cannot certify conformance.

### OracleEvidenceProfileEnvelope

```yaml
OracleEvidenceProfileEnvelope:
  schema_version: ioi.oracle-evidence-profile.v1
  oracle_evidence_profile_id: oracle-evidence-profile://...
  system_id: system://...
  version: semver_or_hash
  fact_class_refs: []
  source_requirements:
    - source_class: official_record | institutional_attestation | signed_sensor | contractual_notice | human_attestation | network_commitment | other
      source_refs: []
      evidence_schema_ref: schema://...
      signer_or_principal_refs: []
      freshness_and_finality_policy_ref: policy://...
      independence_group_ref: optional
      required: boolean
  aggregation:
    rule: single_source | threshold | weighted | adjudicated
    minimum_sources: positive_integer
    minimum_independent_principals: positive_integer
    threshold_policy_ref: policy://... | null
    correlated_failure_policy_ref: policy://...
    uncertainty_policy_ref: policy://...
  contradiction:
    policy: fail_closed | hold_pending | escalate
    adjudicator_refs: []
    dispute_policy_ref: policy://...
  challenge:
    challenge_window_ref: policy://...
    verifier_refs: []
    appeal_policy_ref: policy://...
  admission:
    decision_semantics: qualified_scope_bound_operational_determination
    ontology_assertion_schema_refs: []
    required_verifier_path_refs: []
    ontology_action_contract_refs: []
    permitted_applicability_scope_refs: []
    permitted_consequence_scope_refs: []
    maximum_assertion_validity_policy_ref: policy://...
    required_authority_refs: []
    policy_ref: policy://...
    receipt_obligations:
      - oracle_evidence_admission
  missing_or_stale_evidence_mode: unknown | read_only | pause | escalate
  source_replacement_policy_ref: policy://...
  privacy_policy_ref: policy://...
  retention_policy_ref: policy://...
  status: draft | active | superseded | revoked
```

Actual observations remain evidence or `OntologyAssertionEnvelope` records.
The profile governs whether attributed, freshness-bounded, contradictory, and
challengeable evidence may support a scoped transition; it does not turn an
external proposition into universal truth. Silence, source loss, creator
absence, or stale data is not positive evidence unless an explicit lawful rule
says so.

The selected profile may compose several mechanisms into a qualified
operational determination only when it binds the fact class, evidence and
dependency roots, independence posture, verifier path, freshness and
uncertainty assessment, contradiction/challenge state, applicability,
permitted-consequence scope, validity window, policy, and required authority.
The resulting `OracleEvidenceAdmissionReceipt` is owned by the receipt registry.
It proves that the named admission boundary reached its declared decision under
those inputs; it does not prove the external proposition and it conveys no
authority by itself.

### LifecycleContinuityProfileEnvelope

```yaml
LifecycleContinuityProfileEnvelope:
  schema_version: ioi.lifecycle-continuity-profile.v1
  lifecycle_profile_id: lifecycle-profile://...
  system_id: system://...
  constitution_ref: constitution://...
  version: semver_or_hash
  continuity_class: operator_bound | successor_governed | durable_purpose | finite_term
  continuity:
    operating_budget_policy_ref: policy://...
    dependency_replacement_policy_ref: policy://...
    minimum_archive_policy_ref: policy://...
    degraded_mode: pause | read_only | bounded_continuation
  recovery_and_suspension:
    recovery_policy_ref: policy://...
    pause_and_resume_policy_ref: policy://...
    suspension_and_reinstatement_policy_ref: policy://...
    quarantine_and_release_policy_ref: policy://...
    retirement_policy_ref: policy://...
  succession:
    enabled: boolean
    trigger_classes: [creator_death, creator_incapacity, organization_dissolution, authority_loss, governance_deadlock, term_expiry]
    oracle_evidence_profile_refs: []
    successor_candidate_refs: []
    selection_policy_ref: policy://...
    required_legal_or_governance_authority_refs: []
    challenge_window_ref: policy://...
    authority_handoff: rotate_and_reissue
    constitution_must_be_preserved: true
  dissolution:
    trigger_policy_refs: []
    approval_policy_ref: policy://...
    active_work_disposition_policy_ref: policy://...
    asset_disposition_contract_refs: []
    outstanding_obligation_policy_ref: policy://...
    authority_revocation_policy_ref: policy://...
    worker_and_node_shutdown_policy_ref: policy://...
    data_export_retention_and_erasure_policy_ref: policy://...
    network_exit_policy_ref: policy://...
    tombstone_policy_ref: policy://...
  migration:
    allowed: boolean
    migration_policy_ref: policy://...
    identity_continuity_required: true
    state_root_verification_required: true
  fork:
    allowed: boolean
    fork_policy_ref: policy://...
    new_system_id_required: true
    source_identity_inheritance: forbidden
    state_root_and_lineage_proof_required: true
  adoption:
    allowed: boolean
    adoption_policy_ref: policy://...
    identity_continuity_decision_profile_ref: policy://...
    explicit_identity_decision_required: true
    state_root_and_lineage_proof_required: true
  status: draft | active | superseded | revoked
```

Succession transfers governed responsibility, not existing raw keys;
wallet.network rotates or reissues authority inside the constitution. Creator
absence never widens purpose. Migration, fork, or adoption does not silently
inherit identity, assurance, reputation, escrow, or enrollment.

### AutonomousSystemHomeDomainBindingEnvelope

```yaml
AutonomousSystemHomeDomainBindingEnvelope:
  schema_version: ioi.autonomous-system-home-domain-binding.v1
  home_domain_binding_ref: system-home-domain-binding://.../sha256:...
  home_domain_binding_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  home_domain_ref: agentgres://domain/autonomous-system/.../sha256:...
  home_domain_commitment: sha256:...
  source_governing_authority_ref: protocol-principal-or-runtime-ref
  source_genesis_admission_receipt_ref: receipt://...
  source_genesis_admission_receipt_root: sha256:...
  source_sequence_zero_materialization_ref: system-materialization://...
  source_sequence_zero_materialization_root: sha256:...
  source_sequence_zero_receipt_ref: receipt://...
  source_sequence_zero_receipt_root: sha256:...
  source_sequence_zero_receipt_artifact_root: sha256:...
  activation_transition_ref: lifecycle-transition://...
  activation_receipt_ref: receipt://...
  status: admitted
  created_at: timestamp
```

Activation admits the first canonical Agentgres home-domain identity. The
domain is derived by a domain-separated commitment over the stable System,
genesis, general source governing authority, and exact M1.3/M1.4 source
coordinates; it is never inferred by treating a wallet, organization, or
runtime principal as a domain. The binding grants no node membership, writer,
runtime, network-enrollment, or settlement authority.

### AutonomousSystemActivationProposalEnvelope

```yaml
AutonomousSystemActivationProposalEnvelope:
  schema_version: ioi.autonomous-system-activation-proposal.v1
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  operation: initialize | activate
  sequence: 1 | 2
  required_scope: scope:autonomous_system.lifecycle.initialize | scope:autonomous_system.lifecycle.activate
  operation_commitment: sha256:...
  authority_effect: exact_closed_server_derived_effect
  authority_effect_hash: sha256:...
  status: proposed
  created_at: timestamp
```

This proposal family is intentionally activation-bootstrap-only. It never
stands for amendment, suspension, succession, migration, dissolution, or
enrollment proposals, and it grants no authority by itself. Each proposal is
an immutable owner object for the exact effect that wallet.network evaluates.

### AutonomousSystemActivationAuthorityDecisionEnvelope

```yaml
AutonomousSystemActivationAuthorityDecisionEnvelope:
  schema_version: ioi.autonomous-system-activation-authority-decision.v1
  decision_ref: decision://...
  decision_root: sha256:...
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  operation: initialize | activate
  sequence: 1 | 2
  required_scope: scope:autonomous_system.lifecycle.initialize | scope:autonomous_system.lifecycle.activate
  operation_commitment: sha256:...
  input_hash: sha256:...
  policy_hash: sha256:...
  effect_hash: sha256:...
  authority_grant_ref: grant://wallet.network/approval/sha256:...
  authority_evidence_ref: system-lifecycle-authority-evidence://...
  authority_evidence_root: sha256:...
  wallet_grant_consumption_ref: wallet.network://approval-effect-consumption/...
  wallet_grant_consumption_evidence_ref: system-lifecycle-authority-consumption://...
  outcome: admitted
  decided_at: timestamp
```

The decision is retained evidence for one activation-bootstrap proposal. Its
effect hash is recomputed from the exact proposal effect; copied or unrelated
wallet evidence cannot authorize a successor.

### AutonomousSystemActivationStateEnvelope

```yaml
AutonomousSystemActivationStateEnvelope:
  schema_version: ioi.autonomous-system-activation-state.v1
  activation_state_ref: system-activation-state://...
  activation_state_root: sha256:...
  system_id: system://...
  sequence: 1 | 2
  status: initialized | active
  predecessor_state_root: sha256:...
  active_profile_set_ref: active-profile-set://... | null
  active_profile_set_root: sha256:... | null
  transition_ref: lifecycle-transition://...
  transition_root: sha256:...
  transition_receipt_ref: receipt://...
  transition_receipt_root: sha256:...
  chain_ref: autonomous-system-chain://... | null
  live_chain_created: boolean
```

The semantic `activation_state_root` excludes transition, receipt, and chain
navigation fields. It commits only predecessor, sequence, status, exact
profile-admission coordinates, and the explicit no-membership/no-runtime/
no-network posture. That exclusion is intentional: downstream evidence may
point back to the state, but the state root never points forward to evidence
whose root depends on it.

### AutonomousSystemActiveProfileSetEnvelope

```yaml
AutonomousSystemActiveProfileSetEnvelope:
  schema_version: ioi.autonomous-system-active-profile-set.v1
  active_profile_set_ref: active-profile-set://...
  active_profile_set_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  profile_bundle_root: sha256:...
  constitution: { candidate_profile_ref, candidate_profile_root, admitted_posture: active }
  deployment: { candidate_profile_ref, candidate_profile_root, admitted_posture: active }
  ordering_admission_finality: { candidate_profile_ref, candidate_profile_root, admitted_posture: active }
  oracle_evidence_profiles: []
  lifecycle_continuity: { candidate_profile_ref, candidate_profile_root, admitted_posture: active }
  network_enrollment: { candidate_profile_ref, candidate_profile_root, admitted_posture: local_only } | null
  activation_transition_ref: lifecycle-transition://...
  activation_receipt_ref: receipt://...
  status: active
```

This set is the activation admission evidence. It does not mutate or relabel
the M1.3 candidate bodies. Required cardinality is structural: exactly one
constitution, deployment, ordering/admission/finality, and lifecycle entry;
oracle entries may repeat only as distinct immutable objects; network
enrollment is absent or one `local_only` candidate. Its semantic root excludes
the downstream transition and receipt navigation refs.

The `ioi.autonomous-system-active-profile-set.v2` successor generalizes the
admission carrier beyond activation:

```yaml
AutonomousSystemActiveProfileSetEnvelope (v2 delta):
  schema_version: ioi.autonomous-system-active-profile-set.v2
  admitted_by_transition_ref: lifecycle-transition://...   # replaces activation_transition_ref
  admitted_by_receipt_ref: receipt://...                   # replaces activation_receipt_ref
  supersedes_profile_set_ref: active-profile-set://...     # required; v2 exists only as a successor
  supersedes_profile_set_root: sha256:...
```

Any admitted lifecycle transition — a constitutional amendment execution
first among them — may carry a v2 set, and every v2 set supersedes an exact
predecessor set by reference and content root. All admission entries, the
required cardinality, the `active` status literal, and the exclusion of
transition/receipt navigation refs from the semantic root carry over
verbatim; the root domain bumps to v2. v1 remains the valid shape for the
activation-admitted set (`predecessor_remains_valid: true`).

### AutonomousSystemProtectedTransitionProposalEnvelope

```yaml
AutonomousSystemProtectedTransitionProposalEnvelope:
  schema_version: ioi.autonomous-system-protected-transition-proposal.v1
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  op: pause | resume | suspend | reinstate | enter_dormancy | wake | begin_recovery | complete_recovery | quarantine | release_quarantine | retire | archive | revoke | decommission
  sequence: positive_integer >= 3
  predecessor_status: active | degraded | paused | suspended | dormant | recovering | quarantined | retired | archived | revoked
  predecessor_state_root: sha256:...
  predecessor_chain_head_root: sha256:...
  irreversibility: reversible | one_way | terminal
  required_scope: scope:autonomous_system.lifecycle.<op>
  operation_commitment: sha256:...
  authority_effect: exact_closed_server_derived_effect
  authority_effect_hash: sha256:...
  status: proposed
  created_at: timestamp
```

This family owns proposals for the generic protected operational transitions
of a live System at sequence three or later. It never stands for bootstrap
initialize/activate (the activation family above), and never for
constitutional amendment, migration/succession, dissolution, or network
enrollment, which retain their named owners. Each proposal binds the exact
live predecessor state root and chain head, so a stale, foreign, or replayed
head admits nothing, and each op carries its own
`scope:autonomous_system.lifecycle.<op>` wallet scope: authority for one
transition kind is never authority for another.

The op-by-predecessor legality table is closed and machine-contracted:

| op | legal predecessor status | resulting status |
| --- | --- | --- |
| `pause` | `active`, `degraded` | `paused` |
| `resume` | `paused` | `active` |
| `suspend` | `active`, `degraded`, `paused` | `suspended` |
| `reinstate` | `suspended` | `active` |
| `enter_dormancy` | `active`, `paused` | `dormant` |
| `wake` | `dormant` | `active` |
| `begin_recovery` | `degraded`, `suspended`, `quarantined` | `recovering` |
| `complete_recovery` | `recovering` | `active` |
| `quarantine` | `active`, `degraded`, `paused`, `recovering` | `quarantined` |
| `release_quarantine` | `quarantined` | `active` |
| `retire` | `active`, `paused`, `suspended`, `dormant` | `retired` |
| `archive` | `retired` | `archived` |
| `revoke` | any non-terminal status | `revoked` |
| `decommission` | `retired`, `archived`, `revoked` | `decommissioned` |

`degraded` is an observed posture, never an op target: no proposal may set it
directly. `archive` is `one_way`; `revoke` is `one_way` and protected;
`decommission` is `terminal`. The proposal must declare the matching
`irreversibility` value so a decision can never silently approve a terminal
effect, and a proposal cannot satisfy its own authority requirements.

### AutonomousSystemProtectedTransitionDecisionEnvelope

```yaml
AutonomousSystemProtectedTransitionDecisionEnvelope:
  schema_version: ioi.autonomous-system-protected-transition-decision.v1
  decision_ref: decision://...
  decision_root: sha256:...
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  op: pause | resume | suspend | reinstate | enter_dormancy | wake | begin_recovery | complete_recovery | quarantine | release_quarantine | retire | archive | revoke | decommission
  sequence: positive_integer >= 3
  irreversibility: reversible | one_way | terminal
  required_scope: scope:autonomous_system.lifecycle.<op>
  operation_commitment: sha256:...
  input_hash: sha256:...
  policy_hash: sha256:...
  effect_hash: sha256:...
  authority_grant_ref: grant://wallet.network/approval/sha256:...
  authority_evidence_ref: system-lifecycle-authority-evidence://...
  authority_evidence_root: sha256:...
  wallet_grant_consumption_ref: wallet.network://approval-effect-consumption/...
  wallet_grant_consumption_evidence_ref: system-lifecycle-authority-consumption://...
  outcome: admitted
  decided_at: timestamp
```

The decision is retained evidence for exactly one protected-transition
proposal. Its effect hash is recomputed from the exact proposal effect;
copied or unrelated wallet evidence cannot authorize a different op,
sequence, or System, and the decision restates the proposal's declared
`irreversibility` so the approved effect class is explicit in the evidence.

### AutonomousSystemLifecycleStateEnvelope

```yaml
AutonomousSystemLifecycleStateEnvelope:
  schema_version: ioi.autonomous-system-lifecycle-state.v1
  lifecycle_state_ref: system-lifecycle-state://...
  lifecycle_state_root: sha256:...
  system_id: system://...
  sequence: positive_integer >= 3
  status: active | paused | suspended | dormant | recovering | quarantined | retired | archived | revoked | decommissioned
  predecessor_state_root: sha256:...
  active_profile_set_ref: active-profile-set://...
  active_profile_set_root: sha256:...
  transition_ref: lifecycle-transition://...
  transition_root: sha256:...
  transition_receipt_ref: receipt://...
  transition_receipt_root: sha256:...
  chain_ref: autonomous-system-chain://...
```

The lifecycle state continues the activation-state chain beyond sequence two
for the generic protected ops. Like the activation state, its semantic
`lifecycle_state_root` excludes transition, receipt, and chain navigation
fields: it commits only the predecessor, sequence, status, and exact
profile-set coordinates, and downstream evidence points back at it without
its root ever depending on that evidence. Succession, dissolution, and
enrollment statuses (`succession_pending`, `successor_governed`,
`dissolution_pending`, `dissolving`, `dissolved`) are reserved for their
named owner families and are not legal values here.

### LifecycleTransitionReceiptEnvelope

```yaml
LifecycleTransitionReceiptEnvelope:
  schema_version: ioi.lifecycle-transition-receipt.v1
  receipt_ref: receipt://...
  receipt_type: lifecycle_transition
  op: initialize | pause | resume | suspend | reinstate | enter_dormancy | wake | begin_recovery | complete_recovery | quarantine | release_quarantine | retire | archive | revoke | decommission
  sequence: positive_integer
  bound_facts:
    operation_commitment: sha256:...
    proposal_ref: proposal://...
    proposal_root: sha256:...
    decision_ref: decision://...
    decision_root: sha256:...
    transition_root: sha256:...
    predecessor_state_root: sha256:...
    resulting_state_root: sha256:...
    chain_ref: autonomous-system-chain://... | null
    live_chain_created: false
  authority_evidence_ref: system-lifecycle-authority-evidence://...
  authority_evidence_root: sha256:...
  wallet_grant_consumption_ref: wallet.network://approval-effect-consumption/...
  required_scope: scope:autonomous_system.lifecycle.<operation>
```

The generic receipt is not frozen to bootstrap. Its `initialize` branch is
closed at sequence one and additionally binds the exact M1.3/M1.4 source,
content-addressed deployment revision, intrinsic policy/module coordinates,
and null active-set/chain posture. Later protected lifecycle branches retain
the closed transition/state/authority core at sequence three or later. Shape
does not admit any later authority. Migration, succession, dissolution,
constitutional amendment, and network enrollment retain their named receipt
owners.

The portable receipt proves its closed receipt identity, operation, sequence,
scope, effect hash, boundary-fact coverage, and the exact proposal, decision,
transition, predecessor, resulting-state, and authority-consumption tuple. It
does not carry the complete operation-owner material needed to recompute the
logical `operation_commitment` in isolation. For the fixed M1.5a prefix, the
compiler therefore reconstructs that commitment from the proposal's exact
authority effect and cross-checks the same value through decision, transition,
receipt, and operation-log entry. Receipt shape alone never admits an
operation.

### AutonomousSystemAmendmentExecutionProposalEnvelope

```yaml
AutonomousSystemAmendmentExecutionProposalEnvelope:
  schema_version: ioi.autonomous-system-amendment-execution-proposal.v1
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  genesis_ref: genesis://...
  op: amend_constitution
  sequence: positive_integer >= 3
  amendment_ref: constitution-amendment://...
  amendment_root: sha256:...
  approval_decision_root: sha256:...
  predecessor_constitution_ref: constitution://...
  predecessor_constitution_root: sha256:...
  successor_constitution_ref: constitution://...
  successor_constitution_root: sha256:...
  changed_field_paths_commitment: sha256:...
  predecessor_status: active | paused
  predecessor_state_root: sha256:...
  predecessor_chain_head_root: sha256:...
  irreversibility: one_way
  required_scope: scope:autonomous_system.lifecycle.amend_constitution
  operation_commitment: sha256:...
  authority_effect: exact_closed_server_derived_effect
  authority_effect_hash: sha256:...
  status: proposed
  created_at: timestamp
```

This family owns the single protected constitutional-amendment execution op,
`amend_constitution`, at sequence three or later. It is distinct from the
generic protected-transition family above and from the non-effecting
`AutonomousSystemConstitutionAmendment` declaration: the declaration proposes
and is approved; this proposal binds the approved declaration
(`amendment_ref` + `amendment_root`) to one exact live execution point. An
amendment is admissible only from an `active` or `paused` predecessor, pinned
by exact state root and chain head, so a stale, foreign, or replayed head
admits nothing.

`scope:autonomous_system.lifecycle.amend_constitution` is its own wallet
scope, disjoint from every one of the fourteen operational transition
scopes: it satisfies none of them and none of them satisfies it. Authority
to pause, resume, or retire a System is never authority to rewrite its
constitution, and vice versa. (The `lifecycle` segment names the daemon's
System-operation authority namespace, which every governed chain operation
shares; the operation segment is what separates authority.) The
op is `one_way` with forward-only rollback: reverting an amendment is a new
amendment over the successor constitution, never an in-place revert, and the
predecessor constitution remains retained, content-addressed superseded
evidence.

`changed_field_paths_commitment` binds the canonical predecessor-to-successor
JSON-pointer diff: a declaration whose changed paths do not equal the
machine-computed diff admits nothing. Structural lineage fields
(schema version, constitution and system identity, version, predecessor ref,
constitution root, activation receipt ref, status) and every path named by
the constitution's own `governance.protected_field_paths` are unamendable
regardless of declaration. `approval_decision_root` binds the distinct
external-governance decision that approved the exact declaration, and
The execution authority effect also binds the durable
`approval_authority_evidence_root`, whose separately signed grant resolves to
the predecessor constitution's external governance owner.
`agent_may_commit_amendment: false` refuses agent-principal execution even
when a grant exists. The embedded closed
effect restates the predecessor/successor constitution roots and the
changed-path commitment, and declares `constitution_changed: true` and
`profile_set_changed: true` as its sole authorized positive effects,
alongside the four retained negative claims (`live_chain_created`,
`node_membership_created`, `runtime_effect_admitted`,
`network_effect_admitted`, all `false`). The swap itself still happens only
at chain commit, exactly once. Operational status never changes through
amendment: the resulting status equals the predecessor status.

### AutonomousSystemAmendmentExecutionDecisionEnvelope

```yaml
AutonomousSystemAmendmentExecutionDecisionEnvelope:
  schema_version: ioi.autonomous-system-amendment-execution-decision.v1
  decision_ref: decision://...
  decision_root: sha256:...
  proposal_ref: proposal://...
  proposal_root: sha256:...
  system_id: system://...
  op: amend_constitution
  sequence: positive_integer >= 3
  amendment_ref: constitution-amendment://...
  amendment_root: sha256:...
  approval_decision_root: sha256:...
  irreversibility: one_way
  required_scope: scope:autonomous_system.lifecycle.amend_constitution
  operation_commitment: sha256:...
  input_hash: sha256:...
  policy_hash: sha256:...
  effect_hash: sha256:...
  authority_grant_ref: grant://wallet.network/approval/sha256:...
  authority_evidence_ref: system-lifecycle-authority-evidence://...
  authority_evidence_root: sha256:...
  wallet_grant_consumption_ref: wallet.network://approval-effect-consumption/...
  wallet_grant_consumption_evidence_ref: system-lifecycle-authority-consumption://...
  outcome: admitted
  decided_at: timestamp
```

The decision is retained evidence for exactly one amendment-execution
proposal. Its effect hash is recomputed from the exact proposal effect and it
restates the amendment declaration coordinates, so copied or unrelated wallet
evidence cannot authorize a different amendment, sequence, or System, and the
restated `one_way` irreversibility makes the approved effect class explicit
in the evidence. An approved amendment is chain-committed exactly once; the
decision never re-executes.

### AutonomousSystemActivationReceiptEnvelope

```yaml
AutonomousSystemActivationReceiptEnvelope:
  schema_version: ioi.autonomous-system-activation-receipt.v1
  receipt_ref: receipt://...
  receipt_type: autonomous_system_activation
  op: activate
  sequence: 2
  bound_facts:
    exact_m1_3_m1_4_and_deployment_coordinates: closed
    home_domain_binding_ref: system-home-domain-binding://.../sha256:...
    home_domain_binding_root: sha256:...
    operation_commitment: sha256:...
    transition_ref: lifecycle-transition://...
    transition_root: sha256:...
    predecessor_state_root: sha256:...
    resulting_state_root: sha256:...
    active_profile_set_ref: active-profile-set://...
    active_profile_set_root: sha256:...
    chain_ref: autonomous-system-chain://...
    live_chain_created: true
```

The specialized activation receipt is the admission boundary that turns the
exact draft constitution and candidate profiles into the first active-profile
evidence. It may bind the deterministic chain ref, but never `chain_root`: the
chain and operation-log roots are derived only after the receipt root exists.

The commitment DAG is normative and machine-contracted: converged M1.4
materialization is committed sequence `0` and the predecessor head;
initialize derives semantic sequence-`1` state from that head, then derives
its transition and portable receipt; activate derives the semantic active
profile set, then sequence-`2` state from the exact sequence-`1` root, then
derives its transition and receipt; only then is the live chain and chain root
derived from sequence `0`, both committed transitions/states/receipts, and the
exact active profiles. No earlier root includes a downstream root.

### AutonomousSystemOperationLogEnvelope

```yaml
AutonomousSystemOperationLogEnvelope:
  schema_version: ioi.autonomous-system-operation-log.v1
  operation_log_ref: agentgres://operation-log/autonomous-system/.../revision/sha256:...
  operation_log_root: sha256:...
  predecessor_operation_log_ref: agentgres://operation-log/autonomous-system/.../revision/sha256:... | null
  predecessor_operation_log_root: sha256:... | null
  snapshot_kind: activation_prefix
  system_id: system://...
  genesis_ref: genesis://...
  home_domain_ref: agentgres://domain/autonomous-system/.../sha256:...
  home_domain_commitment: sha256:...
  home_domain_binding_ref: system-home-domain-binding://.../sha256:...
  home_domain_binding_root: sha256:...
  policy_root: sha256:...
  module_registry_root: sha256:...
  upgrade_policy_ref: policy://...
  activation_prefix:
    sequence_zero: exact_committed_m1_4_entry
    sequence_one: exact_committed_initialize_entry
    sequence_two: exact_committed_activate_entry
  entries:
    - { sequence: 0, entry_kind: sequence_zero_materialization, operation_owner_profile_ref: schema://..., operation_owner_ref: system-materialization://..., operation_owner_root: sha256:..., ... }
    - { sequence: 1, entry_kind: system_initialization, operation_owner_profile_ref: schema://..., operation_owner_ref: lifecycle-transition://..., operation_owner_root: sha256:..., ... }
    - { sequence: 2, entry_kind: system_activation, operation_owner_profile_ref: schema://..., operation_owner_ref: lifecycle-transition://..., operation_owner_root: sha256:..., ... }
  head_entry: exact_latest_entry
  latest_sequence: nonnegative_integer
  latest_operation_commitment: sha256:...
  latest_transition_commitment_ref: transition://... | null
  latest_transition_ref: lifecycle-transition://... | null
  latest_transition_root: sha256:... | null
  latest_receipt_ref: receipt://...
  latest_receipt_root: sha256:...
  latest_state_ref: URI | null
  latest_state_root: sha256:... | null
  status: committed
  created_at: timestamp
```

This is the one canonical System operation-log owner. The M1.5a contract is an
immutable content-addressed activation-prefix revision and admits only the
exact sequence-zero, initialize, and activate entries `0/1/2`. It never mutates
prior evidence. Successor-revision schema evolution is deliberately deferred:
before any protected M1.5 operation is admitted, that operation owner's
contract, compiler, and replay path must define and reconstruct append-only
contiguity against this predecessor log and prove that the successor head is
the terminal appended entry. This cut implements no generic successor shape or
later lifecycle authority.

The activation prefix is fully closed. Sequence zero carries the M1.4
operational commitment; initialize and activate carry no
`StateTransitionCommitment`, because their continuity is supplied by exact
predecessor/resulting state roots, transition roots, and portable receipts.
The first active head therefore has `latest_transition_commitment_ref: null`.
`upgrade_policy_ref` is inherited exactly from the admitted constitution; its
presence binds the governing policy and does not perform an upgrade.


The v1 log is deliberately closed to the activation prefix: exactly three
entries, `snapshot_kind: activation_prefix`, and `latest_sequence: 2`. The
`ioi.autonomous-system-operation-log.v2` successor generalizes the log for
protected transitions at sequence three or later — `snapshot_kind:
lifecycle_log`, unbounded entries (minimum three), `protected_transition`
entry kind, and a v2 root domain — while retaining the closed activation
prefix verbatim as an embedded sub-object, so the bootstrap evidence keeps
its exact v1 shape inside the general log. v1 remains the valid shape for
the committed sequence-two revision (`predecessor_remains_valid: true`);
pairwise portable invariants pin the prefix mirror, the 0-to-1 and 1-to-2
continuity, and the head projection, while general entry-to-entry continuity
at sequence three or later is enforced by the daemon and proven by the
journey verifier rather than by index-fixed portable rules.

### AutonomousSystemMigrationDestinationAcknowledgementEnvelope

```yaml
AutonomousSystemMigrationDestinationAcknowledgementEnvelope:
  schema_version: ioi.autonomous-system-migration-destination-acknowledgement.v1
  acknowledgement_ref: migration-destination-acknowledgement://...
  acknowledgement_root: hash
  system_id: system://...
  predecessor_state_ref: system-activation-state://... | system-lifecycle-state://...
  predecessor_state_root: hash
  predecessor_chain_head_root: hash
  source_deployment_profile_ref: deployment-profile://...
  destination_ref: deployment-profile://...
  acknowledged_state_root: hash
  required_scope: scope:autonomous_system.continuity.migration_destination_acknowledge
  operation_commitment: hash
  authority_effect_material: exact_closed_governed_effect
  authority_grant_refs: [grant://...]
  authority_evidence_ref: system-lifecycle-authority-evidence://...
  authority_evidence_root: hash
  wallet_consumption_ref: wallet.network://approval-effect-consumption/...
  wallet_consumption_root: hash
  receipt_ref: receipt://...
  receipt_root: hash
  status: committed
  created_at: timestamp
```

Migration consumes only the ref and root of this separately authorized,
durably retained acknowledgement. The acknowledgement binds the exact live
state and chain head, the current deployment profile, a distinct destination,
the governing authority, and the wallet consumption that certified the target
held the same state root. Local and Agentgres copies must agree byte-for-byte
before the chain transition can compile; a caller-supplied destination or bare
state-root assertion is not migration evidence.

### AutonomousSystemContinuityStateEnvelope

```yaml
AutonomousSystemContinuityStateEnvelope:
  schema_version: ioi.autonomous-system-continuity-state.v1
  lifecycle_state_ref: system-lifecycle-state://...
  lifecycle_state_root: hash
  system_id: system://...
  sequence: integer >= 3
  status: active | succession_pending | successor_governed | dissolution_pending | dissolved
  predecessor_state_root: hash
  transition_ref: lifecycle-transition://...
  transition_root: hash
  transition_receipt_ref: receipt://...
  transition_receipt_root: hash
  active_profile_set_ref: active-profile-set://...
  active_profile_set_root: hash
  governing_authority_ref: worker://... | service://... | org://... | domain://... | agentgres://domain/...
  pending_successor_candidate_ref: principal_or_organization_ref | null
  network_enrollment_ref: network-enrollment://... | null
  network_enrollment_root: hash | null
  migration_destination_ref: agentgres://... | deployment-profile://... | artifact://... | null
  chain_ref: autonomous-system-chain://...
  created_at: timestamp
```

This state owner is disjoint from the generic operational lifecycle-state
family. Its semantic root uses the same acyclic state-root profile while its
closed status family admits only the named M1.5d continuity outcomes. The root
also binds the current governing principal, the exact candidate selected by a
pending succession, and the content root of any current enrollment. Succession
completion must match the pending candidate and installs a distinct reissued
principal into the live chain; enrollment exit must load and compare the exact
committed enrollment bytes.

### AutonomousSystemNetworkEnrollmentTransitionEnvelope

```yaml
AutonomousSystemNetworkEnrollmentTransitionEnvelope:
  schema_version: ioi.autonomous-system-network-enrollment-transition.v1
  lifecycle_transition_id: lifecycle-transition://...
  system_id: system://...
  op: enroll_local | exit_local_enrollment
  sequence: integer >= 3
  proposal_ref: proposal://...
  proposal_root: hash
  decision_ref: decision://...
  decision_root: hash
  predecessor_state_root: hash
  resulting_state_root: hash
  predecessor_enrollment_ref: network-enrollment://... | null
  predecessor_enrollment_root: hash | null
  resulting_enrollment_ref: network-enrollment://... | null
  resulting_enrollment_root: hash | null
  operation_commitment: hash
  authority_effect_material: closed_effect_with_null_operation_commitment
  authority_grant_refs: [grant://...]
  receipt_refs: [receipt://...]
  status: committed
```

Enrollment admission and exit are compare-and-swap transitions. Admission
requires a resulting enrollment; exit requires the exact predecessor and a
null result. Portable invariants recompute the operation commitment and mirror
the System, sequence, state roots, and enrollment identity/content roots from
the governed effect material. This record does not grant connection, services,
assurance, L1 membership, writing, finality, or settlement.

### LifecycleTransitionEnvelope

```yaml
LifecycleTransitionEnvelope:
  schema_version: ioi.lifecycle-transition.v1
  lifecycle_transition_id: lifecycle-transition://...
  system_id: system://...
  resulting_or_related_system_id: system://... | null
  lifecycle_profile_ref: lifecycle-profile://...
  transition_kind: initialize | activate | pause | resume | suspend | reinstate | enter_dormancy | wake | begin_recovery | complete_recovery | quarantine | release_quarantine | initiate_succession | complete_succession | initiate_dissolution | complete_dissolution | migrate | fork | adopt | retire | archive | revoke | decommission
  genesis_ref: genesis://... | null
  manifest_ref: package://.../release/... | null
  admitted_manifest_root: hash | null
  previous_state: draft | initialized | active | degraded | paused | suspended | dormant | recovering | quarantined | succession_pending | successor_governed | dissolution_pending | dissolving | dissolved | retired | archived | decommissioned | revoked
  proposed_state: same_enum
  trigger_evidence_refs: []
  oracle_evidence_profile_refs: []
  proposal_ref: proposal://...
  decision_ref: decision://... | null
  authority_grant_refs: []
  challenge_opened_at: timestamp | null
  challenge_closes_at: timestamp | null
  predecessor_state_root: hash
  resulting_state_root: hash | null
  operation_commitment: hash | null
  state_transition_commitment_ref: transition://... | null
  lineage_ref: provenance://... | null
  identity_continuity_decision_ref: decision://... | null
  disposition_receipt_refs: []
  receipt_refs: []
  public_commitment_ref: commitment://... | settlement://... | tx://... | null
  status: proposed | evidence_pending | challenge_open | approved | executing | committed | rejected | rolled_back | failed_closed
```

`initialize` and `activate` require `genesis_ref`, manifest/release binding, and
the applicable genesis or activation receipt. Every other transition requires
those fields to be null and operates against the already active system chain.
The genesis object and lifecycle projection may not disagree: only an admitted
lifecycle transition changes whether the system is initialized or active.

A `proposed` lifecycle transition carries no decision, authority grant,
resulting state root, logical operation commitment, M2 state-transition
commitment, disposition receipt, transition
receipt, or public commitment. A `committed` transition requires a decision,
at least one authority grant, the resulting state root, a non-null logical
`operation_commitment`, and at least one receipt. Committed `initialize` and
`activate` transitions require `state_transition_commitment_ref: null`: their
M1 continuity is the exact predecessor/resulting state roots, logical operation
commitment, transition root, and portable receipt. Other protected M1.5
transitions may also commit before M2 with that field null. A non-null
`state_transition_commitment_ref` is present only when the separately owned M2
membership/writer/finality contract actually exists; schema shape never claims
that authority. Public settlement remains optional.

Migration preserves `system_id` and therefore sets
`resulting_or_related_system_id` to the same identity. A fork mints a different
system ID and binds lineage without inheriting enrollment, assurance,
reputation, escrow, or authority. Adoption binds the abandoned/source system
and the governed continuity decision; it preserves identity only when the
constitution and adoption decision explicitly authorize that result.

### IOINetworkEnrollmentEnvelope

```yaml
IOINetworkEnrollmentEnvelope:
  schema_version: ioi.network-enrollment.v1
  network_enrollment_id: network-enrollment://...
  system_id: system://...
  constitution_ref: constitution://...
  manifest_ref: package://.../release/...
  version: semver_or_hash
  predecessor_enrollment_ref: network-enrollment://... | null
  profile: ioi_compatible | ioi_connected | ioi_secured
  governing_decision_ref: decision://...
  authority_grant_refs: []
  effective_at: timestamp
  expires_at: timestamp | null
  renewal_policy_ref: policy://...
  conformance:
    kernel_release_root: hash
    conformance_profile_refs: []
    conformance_receipt_refs: []
    ecosystem_assurance_profile_refs: []
  connection:
    network_ref: network://ioi-l1 | null
    system_registration_ref: optional
    constitution_commitment_ref: optional
    release_commitment_ref: optional
    endpoint_commitment_refs: []
    aiip_profile_refs: []
    aiip_channel_refs: []
  selected_network_services:
    - service_kind: registry | rights | reputation | escrow | dispute | settlement | validator | verifier | guardian | availability | relayer | arbitrator | ordering | finality
      service_ref: service://...
      terms_ref: terms://...
      fee_basis_ref: fee-basis://... | null
      bond_or_stake_ref: optional
      slashing_or_claim_policy_ref: policy://... | null
      assurance_profile_ref: assurance-profile://... | null
  assurance_claim: none | connected_services_only | secured_profile
  standard_das_conformance_profile_ref: conformance-profile://... | null
  exit:
    exit_policy_ref: policy://...
    outstanding_obligation_refs: []
    dispute_refs: []
    final_commitment_ref: optional
  suspension_reason_code: string | null
  transition_receipt_refs: []
  status: local_only | pending | active | suspended | exiting | exited | revoked
```

`ioi_compatible` requires `local_only`, no L1 dependency, no selected network
service, and no assurance claim. `ioi_connected` pays only for named services
and may claim only their guarantees. `ioi_secured` requires Standard DAS
conformance, named security/assurance services, and any declared bonds or
service consideration. Enrollment never taxes local transitions or implicitly
changes constitution, authority, ordering, or finality. Exit preserves open
disputes, outstanding obligations, and required commitments.

The profile conditions fail closed. `ioi_connected` cannot become `active`
without a network ref and at least one complete selected-service record.
`ioi_secured` additionally requires a current Standard DAS conformance ref and
at least one named shared-security/assurance service with service terms,
coverage/fault-model evidence, and any required bond or claim policy. Missing,
expired, suspended, or contradictory prerequisites keep the enrollment pending
or suspended and prohibit the corresponding assurance claim. An active
connected or secured enrollment also requires non-empty authority-grant and
transition-receipt refs. An active secured enrollment additionally requires
non-empty conformance receipts.

### AutonomousSystemChainEnvelope

```yaml
AutonomousSystemChainEnvelope:
  schema_version: ioi.autonomous-system-chain.v1
  chain_ref: autonomous-system-chain://...
  chain_root: sha256:...
  system_id: system://...
  home_domain_ref: agentgres://domain/autonomous-system/.../sha256:...
  home_domain_binding_ref: system-home-domain-binding://.../sha256:...
  home_domain_binding_root: sha256:...
  governance_owner_refs: []
  genesis_ref: genesis://...
  genesis_admission_record_root: sha256:...
  package_id: package://...
  manifest_ref: package://.../release/...
  admitted_manifest_root: sha256:...
  constitution_ref: constitution://...
  constitution_root: sha256:...
  deployment_profile_ref: deployment-profile://.../revision/sha256:...
  deployment_profile_root: sha256:...
  ordering_admission_finality_profile_ref: ordering-profile://...
  oracle_evidence_profile_refs: []
  lifecycle_continuity_profile_ref: lifecycle-profile://...
  network_enrollment_ref: network-enrollment://... | null
  active_profile_set_ref: active-profile-set://...
  active_profile_set_root: sha256:...
  node_membership_refs: []
  node_membership_root: sha256:...
  active_writer_epoch: nonnegative_integer | null
  latest_sequence: nonnegative_integer
  latest_operation_commitment: sha256:...
  latest_transition_commitment_ref: transition://... | null
  latest_transition_id: lifecycle-transition://...
  latest_transition_root: sha256:...
  latest_receipt_ref: receipt://...
  latest_receipt_root: sha256:...
  latest_state_ref: system-activation-state://...
  latest_state_root: sha256:...
  worker_instance_refs: []
  workflow_refs: []
  active_component_registry_ref: agentgres://object-set/autonomous-system-components/sha256:...
  active_component_registry_root: sha256:...
  policy_root: sha256:...
  module_registry_root: sha256:...
  pending_proposal_refs: []
  proposal_queue_root: sha256:...
  operation_log_ref: agentgres://operation-log/autonomous-system/.../revision/sha256:...
  operation_log_root: sha256:...
  upgrade_policy_ref: policy://...
  settlement_policy_ref: policy://... | null
  default_settlement_mode: local_domain | bilateral | invoice | external_escrow | external_chain | ioi_l1 | null
  allowed_settlement_modes: []
  settlement_profile_refs: []
  public_commitment_policy_ref: policy://... | null
  status: draft | initialized | active | degraded | paused | suspended | dormant | recovering | quarantined | succession_pending | successor_governed | dissolution_pending | dissolving | dissolved | retired | archived | decommissioned | revoked
  created_at: timestamp
```

The chain is compact and cross-stage: the canonical operation log exclusively
owns ordered history, while the chain carries only current identity/profile/
component coordinates and the compact latest operation, transition, receipt,
and state head. Replay must load and reconstruct the exact log revision and
cross-check its head against these latest fields.

The first `active` chain proves constitutional and logical continuity only. It
intrinsically binds the admitted home-domain owner, the exact immutable
operation-log activation prefix, the M1.3 ordering/admission/finality
`policy_root`, a domain-separated empty module-registry root, and the
constitution's `ordinary_upgrade_policy_ref`. Binding that policy performs no
upgrade. Its membership, worker, workflow, pending-proposal, settlement, and
public-commitment collections are empty; writer epoch, M2
`StateTransitionCommitment`, settlement policy, and public-commitment policy
are null. Those typed coordinates, not a second Boolean posture object, state
the M1.5a nonclaims.

The v1 chain is not activation-frozen. Later admitted owners may advance
membership, writer, modules, proposals, enrollment, settlement, and transition
commitments while retaining this same contract. Initial empty/null facts are
proved by the M1.5a compiler rather than global schema invariants.

`system_id` remains stable across package releases, node replacement, failover,
migration, and legal/governance succession. Member nodes act for the system only
within their scoped membership and current epoch; no physical node owns the
logical identity.

The deployment, ordering/finality, oracle, lifecycle, and enrollment refs above
are the active admitted refs. They need not remain equal to the package templates
or genesis bindings, but every supersession binds predecessor/proposed roots,
the constitution's protected decision profile, authority, evidence, and
receipts. A chain may not point at an unadmitted profile merely because a
manifest or client requests it.

The active component registry is the live System binding for admitted
GoalRunProfile, WorkflowTemplate, AutomationSpec,
AutomationInstallationBinding, DataRecipe, SkillEntry, RuntimeToolContract,
HarnessProfile, and AgentHarnessAdapter revisions, plus any independently
admitted System-scoped MCP gateway-profile revisions. It is not a copy of
package contents. Every entry binds an exact immutable revision and content or
binding hash. Its root changes only through a governed operation with
predecessor, policy, authority, compatibility, and receipt evidence.
Per-invocation ActiveSkillSetSnapshots, ContextLeases, RuntimeAssignments, and
gateway profiles scoped to one Session or run remain below the System registry.

```yaml
HypervisorNodeEnvelope:
  node_id: node://...
  owner_id: wallet://... | org://... | project://...
  hypervisor_ide_ref: optional
  daemon_runtime_ref: runtime://...
  agentgres_domain_ref: agentgres://domain/...
  wallet_authority_ref: wallet://...
  local_registry_refs:
    workers: []
    modules: []
    workflows: []
    manifests: []
  supported_autonomous_system_node_roles: []
  autonomous_system_membership_refs: []
  node_attestation_refs: []
  failure_domain_refs: []
  receipt_store_ref: agentgres://...
  replay_store_ref: agentgres://...
  settlement_adapter_refs: []
  hosting_posture: local | hosted | hybrid | enterprise
  status: candidate | active | draining | suspended | archived | revoked
```

A Hypervisor Node may participate in several logical systems under separate
membership, role, authority, settlement, and fencing records. A node may expose
settlement adapters, but the logical system's profile selects whether to use
one. `hosting_posture` describes placement/administration; `status` describes
observed node lifecycle.

```yaml
HypervisorOSNodeEnvelope:
  node_id: runtime://...
  profile: hypervisoros_bare_metal
  owner_ref: wallet://... | provider://...
  daemon_ref: runtime://...
  boot_profile_ref: boot_profile://...
  measurement_policy_ref: measurement_policy://...
  ctee_policy_ref: policy://...
  agentgres_domain_ref: agentgres://domain/...
  supported_worker_substrates:
    - microvm
    - container
    - wasm
    - model_server
  forbidden_bypasses:
    - direct_plaintext_private_mount
    - unreceipted_tool_execution
    - raw_secret_env_injection
    - daemonless_model_server
    - unscoped_network_egress
  receipts_required:
    - HypervisorOSBootReceipt
    - NodeMeasurementReceipt
    - ModelMountReceipt
    - CapabilityExitReceipt
```

## LocalAgentPairingSessionEnvelope

`LocalAgentPairingSessionEnvelope` is the short-lived, pre-AIIP bootstrap
contract for connecting an already-running, user-owned local agent or harness
to an IOI product surface. It binds one product-initiated pairing challenge to
one local client key and origin so the client can submit typed proposals
without receiving ambient product, room, runtime, or authority access.

Pairing has three target kinds:

- `room_guest` creates a room-scoped, unpublished Worker composition proposal
  and a typed request to participate in one discoverable OutcomeRoom;
- `private_worker` proposes a reusable Worker composition visible only to the
  initiating user until separately admitted or published;
- `organization_worker` proposes a reusable Worker composition to an
  organization-controlled admission path. Pairing does not prove that the
  agent represents the organization and does not bypass organization policy.

The pairing transport may be a loopback exchange, a device-code flow, or a
copyable bootstrap command. Those are transport choices, not protocol identity
or authority. Raw one-time factors, access tokens, private keys, prompts, and
secrets must not be persisted in this envelope.

```yaml
LocalAgentPairingSessionEnvelope:
  pairing_session_id: local-agent-pairing://...
  schema_version: ioi.local-agent-pairing-session.v1
  initiated_by_ref: user://... | org://...
  initiating_surface_ref: surface://...
  target_kind: room_guest | private_worker | organization_worker
  target_scope_ref:
    outcome-room://... | user://... | org://...
  room_discovery_ref: room-discovery://... | null
  claimed_local_agent:
    display_name: string
    resolver_kind: harness_profile | agent_harness_adapter | none
    resolver_revision_ref:
      harness-profile://.../revision/... |
      agent-harness-adapter://.../revision/... | null
    resolver_content_hash: hash | null
    semantic_harness_profile_revision_ref:
      harness-profile://.../revision/... | null
    semantic_harness_profile_content_hash: hash | null
    execution_posture: instrumented_adapter | prompt_only
  pairing_transport: loopback | device_code | copy_command
  challenge: null | object
    challenge_hash: hash
    authentication_factor_kind:
      one_time_challenge | device_code | signed_nonce
    issued_at: timestamp
    expires_at: timestamp
    single_use: true
  client_binding: null | object
    agent_public_key_ref: key://...
    proof_of_possession_hash: hash
    origin_kind: loopback_endpoint | device_client | bootstrap_client
    origin_binding_hash: hash
    bound_at: timestamp | null
  claim_attempt_policy:
    failed_attempt_limit: positive_integer
    failed_attempt_count: nonnegative_integer
    rate_limit_policy_ref: policy://...
  allowed_bootstrap_actions:
    - read_discovery
    - submit_worker_composition
    - submit_room_participation_request
  bootstrap_non_grants:
    authority: none
    room_membership: none
    room_database_access: none
    private_context_access: none
    connector_or_secret_access: none
    budget_or_spend: none
    effect_execution: none
  submission_refs:
    worker_composition_ref: composition://... | null
    room_participation_request_ref: participation-request://... | null
    first_aiip_packet_ref: packet://... | null
  contribution_lane: instrumented_candidate | proposal_only
  assurance_posture:
    pairing_proves: client_key_and_origin_binding_only
    prompt_only_ceiling: attested
  failure_reason_code:
    null | challenge_expired | challenge_replayed | invalid_proof |
    key_mismatch | origin_mismatch | attempt_exhausted | rate_limited |
    scope_escalation | malformed_submission | policy_denied |
    target_unavailable
  created_at: timestamp
  updated_at: timestamp
  completed_at: timestamp | null
  status:
    created | challenge_issued | agent_proof_received | bootstrap_bound |
    composition_submitted | participation_submitted | completed | expired |
    rejected | cancelled | revoked | failed_closed
```

The subobjects are phase-qualified. `challenge` is null until
`challenge_issued`; after that successful transition, later active states retain
the non-secret challenge commitment and timestamps. `client_binding` is null
until candidate proof is received. In `agent_proof_received`, the candidate
key, proof-of-possession hash, and observed origin binding may be recorded while
`bound_at` remains null; `bootstrap_bound` and later successful states require
all binding fields and a non-null `bound_at`. A terminal transition retains only
the partial subobjects reached before failure: for example, cancellation from
`created` may retain null challenge and binding, while rejection after proof
retains the challenge and observed unbound proof. Terminal states never
synthesize unobserved fields. Failed claims increment `failed_attempt_count`
atomically, and reaching the limit produces `attempt_exhausted` plus
`failed_closed`. Prompt-only clients still bind a bootstrap-client `key://...`
and origin; their limitation is absent runtime instrumentation, not absent
pairing identity.

The `allowed_bootstrap_actions` list is a closed enum and a target-specific
subset, never an extensible capability bag. `read_discovery` exposes only the
signed public or permissioned discovery projection already eligible for the
initiating product session. `submit_worker_composition` and
`submit_room_participation_request` submit tainted proposals for schema and
policy admission. They do not install, invoke, publish, list, admit, allocate,
fund, or authorize the proposed Worker.

`resolver_kind` discriminates the exact resolver revision/hash. `none`
requires both resolver fields to be null. When the local agent uses an
AgentHarnessAdapter, the optional semantic HarnessProfile pair declares the
exact scoped-step contract the adapter realizes; the concrete bridge never
masquerades as that profile. When `resolver_kind: harness_profile`, the
semantic pair equals the resolver pair. `prompt_only` does not imply an
instrumented adapter or verifiable local execution.

The canonical lifecycle is:

```text
created
  -> challenge_issued
  -> agent_proof_received
  -> bootstrap_bound
       -> composition_submitted
            -> completed                         private_worker | organization_worker
            -> participation_submitted
                 -> completed                    room_guest

any non-terminal state
  -> expired | rejected | cancelled | failed_closed

bootstrap_bound | composition_submitted | participation_submitted
  -> revoked
```

For `room_guest`, `participation_submitted` is valid only after a composition
ref exists and the bound client submits the typed
`RoomParticipationRequestEnvelope`. That submission is carried as the first
`room_participation` AIIP packet; the pairing exchange itself is not AIIP and
is not an `authority_grant`. For `private_worker` and `organization_worker`, a
composition proposal is sufficient to complete pairing. Joining a room later
requires a room-specific participation request and the applicable AIIP flow.
`target_scope_ref` must be an `outcome-room://...`, `user://...`, or `org://...`
ref for `room_guest`, `private_worker`, or `organization_worker` respectively;
`room_discovery_ref` is required for `room_guest` and null for the reusable
Worker targets. A mismatch fails closed.

A challenge is short-lived and single-use. Its successful proof is consumed
atomically with binding to the declared client key and origin. A retry may be
idempotent only for the same session, key, origin, target, and submission hash.
Replay, expiry, key or origin drift, target mutation, malformed typed objects,
or a request for any action outside the closed bootstrap set fails closed and
creates no partial grant. Revocation stops future bootstrap use but does not
erase an already admitted composition, participation request, contribution,
or required audit history; those objects follow their own lifecycle owners.

`prompt_only` means the product can authenticate the bootstrap client but
cannot attest which model, harness loop, tools, environment, or private
reasoning produced a proposal. It therefore forces the `proposal_only`
contribution lane and the `attested` prompt-only ceiling. A later named verifier
may advance a specific result through evidence, verification, and acceptance;
that does not retroactively attest the hidden agent runtime.

Pairing completion records bootstrap submission only. Later admission,
rejection, suspension, or revocation of the Worker composition or room
participation request stays on those downstream objects and does not rewrite
pairing history.

No new pairing receipt type is introduced. The session object, its bound
submission refs, and the existing Worker, participation, evidence,
verification, acceptance, and runtime event/receipt owners carry the relevant
state and assurance claims.
