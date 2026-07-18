# Institutional Learning Boundary Conformance

Status: target Hypervisor Core conformance contract; v1.0.
Owners: Hypervisor Core, Agentgres, Foundry, model router, Private Workspace,
Ontology/Data governance, and authority adapters.
Canonical owner: this file for executable pass/fail behavior of an Enterprise
Learning Boundary deployment.
Doctrine owner:
[`../../architecture/foundations/institutional-learning-boundary.md`](../../architecture/foundations/institutional-learning-boundary.md).
Supersedes: demonstrations that infer enterprise-owned learning from a privacy
toggle, provider promise, successful training job, or model swap alone.
Superseded by: none.
Last alignment pass: 2026-07-13.
Implementation status: target; no current product surface may claim this profile
passes until a deployed runner emits the complete report defined below.

## 1. Purpose

This contract tests one end-to-end proposition:

> Governed institutional material can improve institution-controlled
> capability, remain unavailable to prohibited providers, sellers, and tenants,
> survive a cognition-provider swap above a declared threshold, and propagate
> rights changes through its derivatives with machine-verifiable evidence.

The test is cross-plane. Passing one model-route, cTEE, Agentgres, Foundry,
export, or UI test is insufficient.

## 2. Conformance Grades

Two grades are registered:

```text
contract
  deterministic fixtures and mock external recipients may prove policy,
  routing, lineage, denial, and receipt behavior in CI

deployment
  the same suite runs against the promoted deployment, real runtime/custody
  posture, production-equivalent network boundary, and live proof adapters
```

`contract` is necessary but cannot authorize an end-to-end product claim.
Only `deployment` may support a deployment-specific Enterprise Learning
Boundary claim, and only for the tested profile revision, routes, runtime,
material classes, and evidence window.

## 3. Required Runner Interface

An implementation may choose its CLI or API names, but an automated runner MUST
be able to perform these operations without UI scraping or free-text parsing:

```yaml
InstitutionalLearningBoundaryConformanceAdapter:
  compile_boundary_profile:
    input: [parent_profile_refs, child_profile_ref, scope_ref]
    output: [effective_policy_hash, decision, conflicts, receipt_ref]
  admit_learning_use:
    input: [subject_refs, intended_use, route_ref, scope_ref]
    output: [decision, reason_codes, effective_policy_hash, receipt_ref]
  invoke_model_route:
    input: [route_ref, run_ref, payload_ref]
    output: [attempt_ref, network_observation_ref, receipt_ref]
  run_foundry_candidate:
    input: [foundry_spec_ref, eligibility_refs, dataset_snapshot_refs]
    output: [candidate_ref, lineage_root, gate_refs, receipt_root]
  export_institutional_intelligence:
    input: [scope_ref, export_policy_ref, recipient_ref]
    output: [bundle_ref, included_refs, excluded_entries, receipt_ref]
  import_institutional_intelligence:
    input: [bundle_ref, receiving_scope_ref, receiving_boundary_profile_ref]
    output: [admitted_refs, excluded_entries, quarantined_refs, receipt_ref]
  execute_model_independence_test:
    input: [baseline_route_ref, replacement_route_ref, export_bundle_ref, benchmark_ref]
    output: [score_delta, unsupported_dependencies, verdict, report_ref]
  revoke_learning_source:
    input: [source_rights_claim_ref, reason_ref]
    output: [revocation_ref, affected_refs, action_refs, receipt_ref]
  query_impact_graph:
    input: [subject_ref]
    output: [upstream_refs, downstream_refs, active_blocks, residual_exposure_refs]
  query_receipt:
    input: receipt_ref
    output: typed_receipt
```

Every deny result MUST expose a stable code and a typed receipt. A successful
API status, process exit, UI badge, model reply, or log substring is not proof.

## 4. Deterministic Fixture

The runner MUST create an isolated fixture with stable synthetic identifiers:

```yaml
fixture:
  organization: org://ilb-conformance
  project: project://ilb-conformance/private-improvement
  system: system://ilb-conformance-sovereign
  second_tenant: org://ilb-conformance-other
  seller: org://ilb-conformance-seller
  confidential_correction: artifact://ilb/correction-canary
  private_evaluation: dataset://ilb/private-eval-canary
  canary: generated_unique_value_not_present_elsewhere
  model_a_route: model_route://ilb/provider-a
  model_b_route: model_route://ilb/replacement-b
  disallowed_external_route: model_route://ilb/external-denied
  custody_qualified_route: model_route://ilb/private-qualified
```

The effective fixture policy MUST:

- allow operational use and project-private improvement of the correction and
  evaluation;
- allow rights-eligible internal evaluation, dataset generation, and candidate
  improvement;
- deny external plaintext on the disallowed route;
- deny provider-model training, seller learning, cross-tenant reuse,
  publication, and unapproved export;
- require `Private` custody and route proof for the private test path;
- bind explicit source-rights claims, retention, derivative, export,
  revocation, and receipt policy;
- declare a quantitative Model Independence benchmark and minimum threshold.

The unique canary MUST occur in both the confidential correction and one
private evaluation case. It MUST NOT occur in public fixture material, route
metadata, test names, expected error payloads, or receipt metadata.

## 5. Stable Failure Classes

At minimum, the runner and participating services MUST normalize these codes:

```text
LearningBoundaryMissing
LearningBoundaryConflict
LearningBoundaryWideningDenied
LearningBoundaryUpgradeRequired
LearningSourceRightsMissing
LearningUseDenied
LearningEgressDenied
ProviderSecondaryUseDenied
RouteRightsUnsatisfied
CustodyPostureUnsatisfied
TrainingEvidenceIneligible
CrossTenantLearningDenied
InstitutionalExportDenied
DerivativeUseRevoked
ModelIndependenceThresholdFailed
LearningBoundaryProofMissing
```

Service-specific errors may be more precise but MUST map to one of these
conformance classes.

## 6. Required Test Cases

### ILB-01 — Profile Compilation Is Fail-Closed

Given organization, project, system, session, GoalRun/run, model-invocation,
transformation, and Foundry-job profiles, the runner MUST prove:

- effective policy is their most-restrictive intersection;
- a child denial cannot be widened by a parent allow;
- conflicting or missing required rights produce a deny;
- the compiled policy hash and exact input revisions appear in a typed
  compilation receipt;
- every session, GoalRun/run, model-invocation, transformation, and Foundry-job
  snapshot remains immutable after compilation; and
- two compilations over canonical-equivalent inputs produce the same hash.

Pass: all assertions hold. Fail: precedence depends on load order, a missing
right defaults to allow, or the receipt cannot reconstruct the decision.

### ILB-02 — Sovereign System Pinning

After the system pins revision `S1`, activate a broader organization or project
revision. The live system MUST remain on `S1`; the broader revision MUST produce
`LearningBoundaryUpgradeRequired` until the system's governed upgrade is
admitted. An emergency revocation already authorized by `S1` MAY narrow or stop
future use immediately and MUST be receipted.

Pass: the system cannot be ambiently widened and the active revision remains
queryable. Fail: an administrator default silently mutates the sovereign
system's learning uses.

### ILB-03 — Source Rights Precede Improvement

Attempt training, distillation, publication, and export with a missing,
disputed, and expired `LearningSourceRightsClaim` in turn. Each operation MUST
fail before dataset or recipient admission. Then admit an internal-evaluation
right only: evaluation MAY proceed, while training and export remain denied.

Pass: rights are use-specific and missing rights fail closed. Fail: inference
or evaluation permission is treated as blanket training permission.

### ILB-04 — Pre-Egress Enforcement

Send the protected payload to `disallowed_external_route`.

Required assertions:

- no DNS, connection, request body, provider invocation, retry, fallback, or
  telemetry carrying the canary crosses the monitored boundary;
- the run emits a `LearningEgressReceipt` with
  `decision: blocked_before_egress`, an effective policy hash,
  recipient/route bindings, material classes and commitment, purpose, and
  network/gateway evidence, but not the protected plaintext;
- fallback does not select a semantically incompatible provider-trust route;
- the operation terminates denied or blocked, never completed.

Pass: denial occurs before network egress. Fail: the provider sees the payload
and IOI records a denial afterward.

### ILB-05 — Standard Is Honest Provider Trust

On a policy-qualified `Standard` route, the runner MUST expose the external
provider, current terms/route-contract revision, retention and secondary-use
posture, and provider-trust classification before admission. A changed or
expired contract MUST invalidate cached eligibility and block or quarantine the
route until re-admitted.

Pass: disclosed provider-trust processing is correctly classified and
version-bound. Fail: `Standard`, zero-data-retention, encryption, or an
aggregator is represented as custody-proven no-provider-trust.

### ILB-06 — Private Is Proof-Bound In Every Operator Mode

Run the Private path once on an IOI-managed fixture and once on a customer or
self-hosted fixture. In both cases, admission MUST require a current
custody-qualified runtime and no-provider-trust model route. Operator identity
alone MUST NOT satisfy the proof.

Pass: both managed and self-hosted Private claims derive from current evidence.
Fail: a toggle, local label, customer ownership, or IOI management alone
satisfies `Private`.

### ILB-07 — Foundry Admits Only Eligible Evidence

Create a Foundry job from the correction and evaluation. The admitted path MUST
bind:

- the immutable effective boundary snapshot and hash;
- source-rights claims and `TrainingEvidenceEligibility` decisions;
- policy-bound views, Data Recipes, source commitments, and retention policy;
- dataset snapshot, candidate, evaluation, promotion, and receipt lineage.

An ineligible copy of the correction MUST be excluded before dataset
materialization. The candidate MUST remain inert until its ordinary promotion,
runtime, and authority gates pass.

Pass: complete lineage exists and ineligible exhaust never becomes training
input. Fail: observability or tenant ownership is treated as automatic
eligibility, or training grants operational authority.

### ILB-08 — Derived Restrictions Survive Transformation

Transform the eligible evidence into a dataset, adapter or checkpoint, worker
or package candidate, and route candidate. Querying any derivative MUST resolve
the source-rights refs, effective boundary hash, derivative policy, and impact
graph path back to the fixture sources.

Pass: each derivative is reachable and governed. Fail: packaging, conversion,
merge, distillation, export, or promotion severs lineage or widens rights.

### ILB-09 — Cross-Tenant And Seller Denial

As the seller and second tenant, request the correction, private evaluation,
memory/context projection, dataset, candidate, aggregate learning contribution,
and performance-revealing private canary result.

Pass: every unconsented request is denied and receipted; no source or derivative
payload crosses tenants. Fail: package authorship, managed hosting, account
administration, anonymization language, or marketplace participation creates
implicit access.

### ILB-10 — Governed Portability

Authorize one `InstitutionalIntelligenceExportBundle`. The runner MUST verify:

- every included entry is rights-eligible for the recipient and destination;
- provider-native or otherwise nonportable dependencies appear in
  `excluded_entries` with reason codes;
- payload and manifest commitments, encryption, lineage root, receipt root,
  retention, revocation, and residual obligations validate;
- Agentgres remains the source of manifest/admission truth and payload bytes
  remain behind artifact refs; and
- import into the receiving scope re-runs source-rights, boundary, authority,
  integrity, privacy, retention, and canonical-owner admission; possession of
  the bundle does not activate excluded, unsupported, or quarantined entries.

Pass: the recipient can validate the bundle and its omissions, and the import
receipt proves a fresh receiving-domain admission. Fail: the export is an
ungoverned database dump, claims completeness despite exclusions, or import
treats possession as permission or activation.

### ILB-11 — Model Independence

Measure the declared task suite on Model A. Then disable Model A, its provider
credentials, provider-native thread/memory state, provider-only tools, and
fallbacks. Restore only material admitted by the export bundle, mount Model B,
and re-run the same suite.

Pass: the score satisfies the declared minimum threshold, all unavailable
dependencies are reported, and no Model A route appears in invocation or
network receipts. Fail: Model A remains reachable, hidden provider state is
used, the threshold is retroactively changed, or the result claims universal
model equivalence.

### ILB-12 — Revocation And Residual Exposure

Revoke the correction's source-rights claim after export and candidate
promotion. The impact graph MUST identify every affected view, dataset,
checkpoint, model, worker, package, route, export, and commitment. Applicable
future use MUST block, quarantine, recall, re-evaluate, or require clean
reconstruction according to policy.

Pass: the graph and actions are complete for the fixture and already-exported
material is recorded as residual exposure. Fail: the system erases historical
receipts, silently leaves a derivative active, or claims weight-level forgetting
without verified unlearning or clean retraining evidence.

### ILB-13 — Public Settlement Is Sparse And Optional

When no network service is selected, no learning payload or commitment MUST be
published. When the fixture explicitly selects a public commitment service,
only the policy-selected hash/rights/revocation commitment may leave the
domain; no correction, eval case, memory, dataset row, weight, or canary may be
published.

Pass: settlement is optional, sparse, and scoped. Fail: L1 receives operational
learning contents or is treated as source-rights, custody, or semantic proof.

### ILB-14 — Receipt And Claim Integrity

Tamper with the profile revision, route contract, source-rights claim, export
manifest, impact result, and one receipt independently. Verification MUST fail
for each tampered object. The report MUST distinguish observed boundary facts
from contractual provider promises and off-platform unknowns.

Pass: tampering is detected and claims remain scoped. Fail: human-readable
labels or unsigned free text override committed policy/evidence.

## 7. LearningEgressReceipt Minimum Assertions

The sole field schema is owned by the daemon
[`LearningEgressReceipt`](../../architecture/components/daemon-runtime/events-receipts-delivery-bundles.md#learning-egress-receipt)
canon. The conformance runner MUST validate that exact registered schema rather
than a local receipt variant.

For every tested crossing it MUST assert:

- `receipt_type: learning_egress`, the exact
  `institutional_learning_boundary_profile_ref`, effective policy hash, and
  boundary-compilation or policy-decision ref;
- source scope, material classes and commitment, source-rights refs, policy-
  bound projections, recipient class/ref, purpose, and representation;
- the applicable execution-privacy posture, model-route contract, customer-
  output rights, provider-use matrix, terms/licenses, retention posture,
  consent/authority, and redaction/declassification refs;
- underlying operation receipts, Agentgres operation refs, revocation-impact
  ref, and assurance stage required by the fixture;
- `decision: blocked_before_egress` with `transfer_status: not_sent` or
  `prevented_before_network_write` for a denied crossing, or
  `decision: admitted` with the observed transfer status for an allowed
  crossing; and
- gateway, network, sandbox, or equivalent evidence binding the request
  commitment before `prevented_before_network_write` is accepted.

Protected content MUST NOT be copied into the receipt. `admitted` proves only
the declared IOI admission boundary, not delivery or what an external recipient
later did. `blocked_before_egress` proves prevention only when the canonical
receipt carries the required enforcement evidence.

## 8. Required Machine Report

The runner MUST emit one signed or committed report:

```yaml
InstitutionalLearningBoundaryConformanceReport:
  report_version: ioi.ilb-conformance.v1
  grade: contract | deployment
  deployment_ref: runtime://... | system://...
  institutional_learning_boundary_profile_ref: learning-boundary://...
  effective_learning_policy_hash: hash
  fixture_commitment: hash
  tested_route_contract_refs: []
  tested_custody_proof_refs: []
  evidence_window: {started_at: timestamp, ended_at: timestamp}
  cases:
    - case_id: ILB-01
      verdict: pass | fail | blocked
      assertion_receipt_refs: []
      failure_codes: []
  packet_or_transport_capture_ref: artifact://... | evidence://...
  model_independence_report_ref: artifact://... | benchmark://...
  impact_graph_report_ref: artifact://... | agentgres://projection/...
  report_commitment: hash
  signer_ref: verifier://... | org://... | system://...
```

Overall verdict rules:

- `pass` requires ILB-01 through ILB-14 to pass with no missing evidence;
- any failed case makes the profile fail;
- unavailable runtime, custody, route, packet-capture, Foundry, export, or
  revocation capability is `blocked`, not skipped or passed;
- a `contract` report cannot be relabeled as `deployment`;
- expiration or change of a tested route contract, custody proof, profile,
  source right, runtime, or verifier invalidates the deployment claim until the
  affected cases are rerun.

## 9. Prohibited Shortcuts

The following never satisfy this contract:

- a “do not train” checkbox without route-contract and receipt enforcement;
- provider policy screenshots or marketing pages as the only evidence;
- blocking after a prohibited payload was already transmitted;
- a private workspace test that ignores the model/API boundary;
- a model swap that retains the first provider's hidden thread or fallback;
- a Foundry success status without source eligibility and derivative lineage;
- deleting a source row and declaring trained weights clean;
- export success without omissions and residual obligations;
- seller or aggregate improvement enabled by default;
- storing private payloads or canaries on IOI L1;
- passing from UI text, logs, model assertions, or process exit code alone.
