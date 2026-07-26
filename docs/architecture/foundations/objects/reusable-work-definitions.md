# Reusable Work-Definition Objects

Status: canonical low-level reference.
Canonical owner: this file for the shared object shapes of `WorkflowTemplateEnvelope`, `SkillManifestEnvelope`, `SkillEntryEnvelope`, and `ActiveSkillSetSnapshotEnvelope`.
Supersedes: the same object definitions when they were carried as H3 sections under `Package Release And Live-System Genesis` in the single-file `common-objects-and-envelopes.md`.
Superseded by: none.
Last alignment pass: 2026-07-25.
Doctrine status: canonical
Implementation status: planned (no durable WorkflowTemplate, SkillManifest, SkillEntry, or ActiveSkillSetSnapshot object plane is admitted; the Workflow Compositor edits workflow drafts only)
Last implementation audit: 2026-07-25

## Purpose

A reusable work definition says *what work is* without saying that any work is
happening. It carries no run state, no authority, no trigger, and no schedule.
These objects were previously buried under bounded-system package genesis, which
obscured that a WorkflowTemplate or SkillManifest is meaningful with no System,
package, or release anywhere in sight.

Boundary, in one line each:

```text
WorkflowTemplate         immutable directed-work graph shape
SkillManifest            immutable procedure and support material
SkillEntry               revisioned owner-scope binding to one SkillManifest revision
ActiveSkillSetSnapshot   exact run-scoped skill selection
```

Standing activation over a WorkflowTemplate revision is `AutomationSpec`; adaptive
pursuit over a goal class is `GoalRunProfile`, owned by
[`goal-pursuit.md`](./goal-pursuit.md). Neither is a WorkflowTemplate.

Term boundaries for every name used here are owned by
[`term-boundaries.md`](../term-boundaries.md).

## WorkflowTemplateEnvelope

`WorkflowTemplateEnvelope` is the Workflow Compositor's reusable directed-work
definition. A released revision is immutable and content-addressed. It may be
referenced by an `AutomationSpec`, a `GoalRunProfile`, a Package, or a typed
one-off `GoalRun`, `AutomationRun`, `WorkRun`, or Foundry job owner, but the
template never runs itself and owns no trigger, schedule, activation history,
live lease, or execution truth.

```yaml
WorkflowTemplateEnvelope:
  schema_version: ioi.workflow-template.v1
  workflow_template_id: workflow-template://...
  revision_ref: workflow-template://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: workflow-template://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | domain://... | ioi://publisher/...
  display_name: string
  description: string
  graph_ref: workflow://... | artifact://... | cid://...
  graph_hash: hash
  parameter_schema_ref: schema://... | null
  input_contract_refs: []
  output_contract_refs: []
  step_contract_refs: []
  dependency_and_handoff_refs: []
  acceptance_and_review_contract_refs: []
  delivery_contract_ref: schema://... | policy://... | null
  selection_hint_refs:
    harness_profile_revision_refs: []
    model_route_refs: []
    worker_refs: []
    provider_refs: []
    verifier_path_refs: []
  runtime_tool_contract_requirement_refs: []
  required_primitive_capabilities: []
  authority_scope_requirement_refs: []
  resource_and_budget_requirement_refs: []
  receipt_policy_ref: policy://... | null
  allowed_override_schema_ref: schema://... | null
  provenance_refs: []
  evaluation_refs: []
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

`selection_hint_refs` are constraints or reproducibility pins, not live
assignments. Daemon admission still resolves eligible workers, harnesses,
models, tools, authority, context, budget, and runtime placement. A patch to a
released template creates a successor revision; it never mutates an active
revision.

Capability, authority, resource, budget, and receipt fields are requirements
or ceilings only. A WorkflowTemplate never contains a concrete authority
grant, capability/context/resource lease, RuntimeAssignment, selected route,
trigger, or run state.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash; deprecation, recall, or revocation changes eligibility without rewriting
the released definition.

## SkillManifestEnvelope

`SkillManifestEnvelope` is the immutable reusable definition of a skill. It
supplies procedure and support material to a model, worker, or harness; it may
reference `RuntimeToolContract` capabilities but cannot execute them, carry
their credentials, or grant their authority.

```yaml
SkillManifestEnvelope:
  schema_version: ioi.skill-manifest.v1
  skill_id: skill://...
  revision_ref: skill://.../revision/...
  version: semver_or_hash
  predecessor_revision_ref: skill://.../revision/... | null
  content_hash: hash
  owner_ref: org://... | project://... | system://... | user://... | ioi://publisher/...
  display_name: string
  description: string
  instruction_entrypoint_ref: artifact://... | cid://...
  procedure_and_reference_refs: []
  example_refs: []
  support_asset_refs: []
  dependency_skill_revision_refs: []
  runtime_tool_contract_requirement_refs: []
  capability_requirement_refs: []
  input_and_output_contract_refs: []
  context_requirement_profile_refs: []
  compatible_goal_run_profile_revision_refs: []
  compatible_harness_profile_revision_refs: []
  compatible_runtime_and_kernel_refs: []
  provenance_refs: []
  source_rights_and_license_refs: []
  evaluation_and_benchmark_refs: []
  promotion_policy_ref: policy://... | null
  revocation_and_recall_policy_ref: policy://... | null
  registry_lifecycle_ref: agentgres://object/... | package://.../release/... | null
  registry_status: draft | evaluable | released | deprecated | revoked
```

Helper scripts may be support assets. Only an agent-callable capability that
crosses an execution/admission boundary requires a `RuntimeToolContract`;
internal helper files do not each become tools merely because a skill invokes
them behind one admitted capability.

The revision body and `content_hash` are immutable. `registry_status` and
`registry_lifecycle_ref` are registry projections excluded from that content
hash.

Commercial discovery is not another skill owner. A Packages/Marketplace
listing or room-scoped `CapabilityOffer` references the exact
`skill_revision_ref` and owns price, license offer, ranking, availability, and
commercial terms. Those fields do not enter `SkillManifest`.

## SkillEntryEnvelope

Each `SkillEntry` is an immutable successor-versioned installation/admission
binding for one organization, Project, workspace, System, or user scope. It
declares the binding's intended enablement posture; the registry projection
owns mutable current lifecycle status. The manifest remains immutable.

```yaml
SkillEntryEnvelope:
  schema_version: ioi.skill-entry.v1
  skill_entry_id: skill-entry://...
  binding_revision_ref: skill-entry://.../revision/...
  predecessor_binding_revision_ref: skill-entry://.../revision/... | null
  binding_hash: hash
  skill_revision_ref: skill://.../revision/...
  skill_manifest_content_hash: hash
  owner_scope_ref: org://... | project://... | system://... | user://...
  memory_space_ref: memory-space://... | null
  compatibility_decision_ref: decision://... | receipt://...
  configuration_ref: artifact://... | policy://... | null
  allowed_goal_run_profile_revision_refs: []
  policy_refs: []
  admitted_by_ref: user://... | org://... | system://...
  admission_receipt_ref: receipt://...
  revocation_ref: revocation://... | null
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: proposed | active | suspended | archived | revoked
```

`SkillEntry` contains no copied procedure body. Each binding revision is
immutable and `binding_hash` commits the exact manifest pin, owner scope,
effective configuration, policy, permitted profile set, and admitting actor.
Changing any of them creates a successor binding revision. Compatibility and
admission decision/receipt refs, revocation, and registry lifecycle/status are
excluded from the hash; they bind the already-computed binding hash and may
suspend or revoke use without rewriting the historical binding. The binding
revision owns the admitted local configuration and enablement declaration; the
registry projection owns mutable lifecycle status. Procedure, provenance,
dependencies, evaluation, promotion, and release recall remain on the manifest
and its referenced owner records.

## ActiveSkillSetSnapshotEnvelope

One admitted run receives an exact, reproducible snapshot of selected skill
revisions and installation bindings. This is live resolution state, not a
portable skill or marketplace asset.

```yaml
ActiveSkillSetSnapshotEnvelope:
  schema_version: ioi.active-skill-set-snapshot.v1
  active_skill_set_snapshot_id: active-skill-set://...
  work_subject_ref:
    goal://... | automation-run://... | work_run://... | run://... |
    invocation://... | work-claim://... | attempt://...
  selected_skills:
    - skill_entry_ref: skill-entry://...
      skill_entry_binding_revision_ref: skill-entry://.../revision/...
      skill_entry_binding_hash: hash
      skill_revision_ref: skill://.../revision/...
      manifest_content_hash: hash
      inclusion_basis_refs: []
  excluded_candidates:
    - candidate_ref: skill://... | skill-entry://...
      reason_code: incompatible | policy_blocked | revoked | superseded | not_required | budget_blocked | other
      decision_ref: decision://... | receipt://...
  compatibility_and_evaluation_result_refs: []
  active_set_hash: hash
  resolved_runtime_tool_contracts:
    - revision_ref: tool://.../revision/...
      content_hash: hash
  context_lease_refs: []
  resolution_receipt_ref: receipt://...
  registry_lifecycle_ref: agentgres://object/... | null
  registry_status: admitted | active | superseded | revoked
```

Runtime hooks remain separately typed executable/admission machinery. A
combined implementation projection such as an active skill-and-hook manifest
must preserve that distinction and normalize to this active-skill-set object
plus separately owned hook bindings.

`active_set_hash` commits each exact SkillEntry binding revision/hash and
SkillManifest revision/hash, the excluded candidates, compatibility results,
resolved tool revisions/hashes, and ContextLease refs. The immutable
`resolution_receipt_ref` links that committed set to admission but is excluded
from the set hash so the receipt may include the snapshot ref/hash without a
self-referential commitment. `registry_lifecycle_ref` and `registry_status` are
also excluded projections; supersession or revocation changes eligibility/use
without rewriting what the run originally resolved.

`work_subject_ref` is mandatory. A snapshot with no exact admitted work binding
fails closed.
