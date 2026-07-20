# Sovereign local completeness conformance

Status: target conformance contract with a canonical machine-readable scenario
matrix. No current sovereign-local-completeness runner, isolated-egress
harness, cross-mode Agentgres parity evaluator, managed attach/detach
evaluator, or identity-preserving migration evaluator is claimed.
Last audited: 2026-07-19.

Canonical inputs:

- [`web4-and-ioi-stack.md`](../../architecture/foundations/web4-and-ioi-stack.md)
  for standalone completeness, zero-to-idle, and managed optionality;
- [`core-clients-surfaces.md`](../../architecture/components/hypervisor/core-clients-surfaces.md)
  for the Hypervisor product posture and client contract;
- [`identity-access-and-metering.md`](../../architecture/components/hypervisor/identity-access-and-metering.md)
  for deployment-local identity, access, and metering;
- [`providers-and-environments.md`](../../architecture/components/hypervisor/providers-and-environments.md)
  for startup, placement, connection, operation, migration, and disconnect;
- [`agentgres/doctrine.md`](../../architecture/components/agentgres/doctrine.md)
  for embedded and server-backed operational truth;
- [`control-plane.md`](../../architecture/domains/ioi-ai/control-plane.md)
  for optional managed account and coordination attachment;
- [`economic-flywheel-and-pricing-boundaries.md`](../../architecture/foundations/economic-flywheel-and-pricing-boundaries.md)
  for local/BYO and managed-work charging boundaries;
- [`platform-operability.md`](../../architecture/components/daemon-runtime/platform-operability.md)
  for degraded operation, disconnected limits, recovery, and protected
  observability; and
- [`execution-horizons.md`](../../architecture/_meta/execution-horizons.md)
  for the selected minimum-L0 journey and ordered proof lanes.

## Scope and honest implementation posture

A deployment is sovereign-locally complete at its declared profile only when
one operator, with every IOI-managed endpoint unavailable, can install and
bootstrap, authenticate, create and admit the selected bounded System, run,
govern, and inspect work, authorize a permitted exact effect, persist and
restart, replay, back up and restore, export and independently verify evidence,
and exercise the selected upgrade, recall, and retirement path through
supported product clients and public contracts.

Conditional capabilities may be typed unavailable or explicitly degraded.
Their absence may not make the declared standalone core unusable. Attaching a
managed service grants only its separately admitted service scopes and never
transfers truth, custody, authority, identity, or writer role without a
separately authorized migration.

Attachment evidence includes a typed protected-substate delta proof. The
Agentgres root may advance for the explicit account/service binding and its
receipt, and a new isolated binding credential may be created with exact scope,
custody, and revocation posture. System and package identities, pre-existing
effect authority and key material, writer role, payload custody,
institutional-learning boundary, and network enrollment remain unchanged.
Billing may add account or entitlement linkage but no usage, debit, or charge.
A custody/writer check or undifferentiated whole-root equality check is
insufficient.

This profile is a cross-owner test contract. It is not a runtime object,
product tier, deployment enum, truth plane, authority provider, billing ledger,
or new application. Fixture and overlay labels in this document classify test
evidence only; they are not canonical deployment enums.

## Claim profiles and required fixtures

| Claim | Required fixture evidence |
| --- | --- |
| `minimum_l0_local_completeness` | `embedded_single_operator_offline` |
| `production_self_hosted` | `embedded_single_operator_offline` plus `self_hosted_org_single_node` |
| `managed_optionality` | one passing standalone fixture plus `managed_attach_detach_overlay` |
| `identity_preserving_migration` | one passing applicable standalone fixture plus `identity_preserving_migration_overlay` |
| `multi_node_high_availability` | separate distributed-operability, membership, durability, and fencing evidence |
| `ioi_managed_hosting` | separate managed-provider, custody, availability, billing, and export evidence |

The machine-readable claim graph makes prerequisite claims transitive:
production self-hosted and managed optionality depend on a passing minimum local
claim, while identity-preserving migration depends on a passing applicable
standalone claim rather than on first-party managed attachment. The scenario
`required_for_claims` index is the sole requirement-to-claim mapping. It must
not be duplicated by a second, independently editable requirement list.
Out-of-scope HA and managed-hosting claims are ineligible in this contract and
cannot pass vacuously.

`embedded_single_operator_offline` uses one admitted node, embedded Agentgres,
local storage, deployment-local identity, a locally permitted authority
provider, and an admitted deterministic fixture or local-model route. Every
IOI-managed, marketplace, IOI Network, IOI L1, license, update, support,
telemetry, and external-model endpoint is blocked. It claims only its declared
single-node durability and failure domain.

`self_hosted_org_single_node` adds a normal customer-controlled server/headless
deployment, server-backed Agentgres, deployment-local or customer OIDC
identity, customer storage, and customer model/BYOK supply. It does not require
HypervisorOS and does not claim multi-node availability. Its server-backed
posture must be compared with the inherited embedded fixture; selecting
embedded twice cannot prove cross-mode parity.

`managed_attach_detach_overlay` starts from a passing standalone fixture,
attaches exactly one named managed service, proves the service's data views,
leases, RuntimeAssignments, custody, charges, and receipts, then revokes or
detaches it. It is an overlay, not another deployment mode.

`identity_preserving_migration_overlay` is required only when a product claims
an identity-preserving placement or custody transition. It binds the applicable
Lifecycle Continuity decision and the complete fenced `HypervisorChangePlan`.
Its source and target operators may be local, customer-managed, IOI-managed, or
hybrid as their placement contracts permit; managed account attachment is not a
prerequisite. Multi-node HA and IOI-managed hosting remain separate conditional
claims and cannot be inferred from local completeness.

## Required runner surface

A future executable runner may provide test-only adapters with the following
semantic operations:

```yaml
configure_network_boundary
bootstrap_deployment
authenticate_deployment_local
admit_locally_permitted_authority
create_and_activate_system
execute_bounded_work
propose_and_admit_effect
query_state_root
crash_and_restart
export_backup
restore_backup
verify_exported_evidence
attach_managed_service
authenticate_connected_account
authorize_connected_effect
use_managed_service
detach_managed_service
execute_change_plan_migration
query_custody_and_writer_state
query_usage_and_billing
emit_conformance_report
```

These operation names are runner methods, not new canonical API objects. An
implementation may bind them to its supported clients and public daemon/domain
contracts, but it may not satisfy a case through hidden database edits,
unpublished privileged scripts, fabricated receipts, or imported success
flags.

## Required behavior

### SLC-01 — Isolated cold boot

A fresh deployment with DNS and non-loopback egress denied must start its
supported local client, daemon, and the fixture's declared Agentgres path
without an
`ioi.ai` account, hosted wallet login, marketplace, IOI Network, IOI L1,
license heartbeat, telemetry, update service, support service, or external
model provider. Loopback and declared local IPC may remain available. Missing
optional planes return typed unavailable or degraded dispositions.

### SLC-02 — Identity and authority separation

The runner bootstraps a deployment-local operator and admits one locally
permitted exact-effect authority path. An authenticated administrator without
effect authority is refused before the invoker and produces zero effect calls.
An exposed binding retains fail-safe authentication. This fixture makes no
portable delegated-authority claim.

### SLC-03 — Closed product vertical

Through supported product clients and public contracts, one reusable package
must produce one stable bounded System, an admitted GoalRun/OutcomeRoom-backed
work path, an isolated attempt, independent deterministic verification, one
successful exact reviewed repository effect with exactly one final-invoker
call, postcondition verification, receipts, an inspectable state root, and the
selected upgrade, rollback or recall, and retirement lifecycle. Client
projections resolve the same owner refs and hashes. A separate adversarial path
proves that missing verification is refused before the invoker. A typed refusal
is valid negative evidence but cannot replace the required successful effect.

### SLC-04 — Custody and zero undeclared egress

Canaries seeded in ontology, memory, traces, evaluations, secrets, workspace,
receipts, diagnostics, and support material must not cross the denied egress
boundary. Only an explicitly admitted route or declassification path may
permit egress. Blocking optional telemetry, diagnostics, crash reporting,
support, licensing, or update discovery cannot disable unrelated local work.

### SLC-05 — Crash, restart, replay, and idempotency

Crashes before and after admission and around a possible effect must recover
the exact admitted heads and roots, reject changed-body replay, and prevent
duplicate effects. An effect whose outcome cannot be established remains
reconciliation-required and never becomes success through retry or restart.

### SLC-06 — Backup, clean restore, and offline proof

The runner exports backup and evidence material, verifies it without an IOI
service, restores it into a clean deployment under the applicable authority
path, and reproduces the declared domain state and receipt lineage. The
imported historical checkpoint root must equal the exported checkpoint root;
the clean deployment's current root normally advances as a valid successor
that binds the restore/admission receipt and freshly resolved deployment
identity, authority, key, provider, custody, writer, and currentness context.
Undifferentiated equality between the source and restored current roots is not
required. Tamper, gaps, wrong checkpoint roots, invalid successor lineage, and
missing predecessors fail closed. Restored grants, revocation state, time
state, or continuity floors cannot silently reactivate or move currentness
backward. An authentic but stale pre-revocation or pre-continuity-floor restore
remains historical or blocked until independently re-anchored; signature
validity alone cannot make it current.

### SLC-07 — Public-contract semantic parity

The selected canonical fixture runs once over embedded Agentgres and once over
an explicitly server-backed Agentgres fixture, then compares canonical inputs
and content commitments, semantic dispositions, public API behavior, receipt
schema and meaning, and replayed declared domain state. Deployment-scoped
identifiers, timestamps, admission or restore receipts, writer epochs, and
current roots may differ; each must validate, preserve owner refs and
successor lineage, and replay to equivalent declared domain state. Byte
equality across independent executions is not semantic parity. A semantic
mismatch fails the production-self-hosted claim. Capacity, SLO,
provider-native, and availability differences remain explicitly outside
semantic parity and retain honest durability labels.

### SLC-08 — Managed attachment without implicit transfer

Attaching an account or managed service may append explicit binding and receipt
truth, add account or entitlement linkage, and create a new isolated, scoped,
revocable binding credential. Its typed delta must show that it changes no
pre-existing System or package identity, effect authority or key material,
writer, payload custody, institutional-learning boundary, or network
enrollment, and creates no usage, debit, or charge.
Managed use begins only through separately reviewed service bindings, data
views, leases, RuntimeAssignments, authority, and receipts. The connected lane
must also prove provider-neutral account authentication and the context-bound
portable authority path, including passkey-capable step-up when policy requires
it. It then successfully uses one named managed service and inspects the exact
binding, data view, lease, assignment, custody, usage, charge, and receipt
chain. The managed invocation must bind the same authority-request body,
reviewed representation, ceremony context, portable grant, service lease, data
view, RuntimeAssignment, invocation body, and postcondition hashes. A mismatch
is refused before the managed invoker and creates no usage charge.
Attachment-without-use and missing-lease refusal are necessary negative cases,
not substitutes for successful managed use.

### SLC-09 — Detachment and dependency closure

After managed leases are revoked and managed endpoints are blocked, locally
satisfiable work and locally owned truth remain operable under their declared
authority, temporal, budget, partition, and fence profiles. Operations that
require the detached capability become typed blocked, unavailable, or
explicitly degraded. There is no account or license lockout and no
post-revocation remote execution.

### SLC-10 — Explicit fenced migration

Connection, discovery, sync, backup, or copying bytes is not migration. The
managed-optionality lane proves that negative independently. A claimed
migration may remain entirely local or customer-controlled: it freezes an
authorized `HypervisorChangePlan`, verifies the target import and readiness,
quiesces and fences the source, admits one cutover/writer epoch, preserves a
rollback window, and records explicit source retention, replica, archive, or
teardown disposition. An interrupted cutover retains source authority or
enters typed reconciliation-required state; it never produces two active
writers. `system_id` is preserved only under an applicable Lifecycle
Continuity decision. A denied continuity decision requires a fork or successor
identity even when the remaining migration plan is otherwise complete. A
passing report is scoped only to its exact source/target runtime operators,
placements, custody profiles, durability profile, and assurance profile; one
local-source fixture cannot generalize across every permitted migration tuple.

The fixtures in this contract select a single-node `single_authority`
ordering/finality profile, so their migration cases require exactly one current
writer and a successor writer epoch. Threshold, BFT, external-finality, or other
profiles require their native membership, quorum, ordering, finality, fencing,
and recovery transition evidence and cannot inherit this single-writer proof.

### SLC-11 — Economic boundary

Customer-borne local, BYO model, BYO tool, BYO provider, and customer-storage
supplier cost produces no managed-provider debit or generic pass-through Work
Credit charge. Attachment alone is not billable. An orchestration,
control-plane, support, or managed-service charge requires an explicit quote or
rate contract, actual named service use, and corresponding usage and billing
receipts.

### SLC-12 — Claim honesty

The report binds the exact matrix and hash, claim entry and hash, tested build,
runner version, fixture and overlay hashes, public-contract versions,
durability, custody, assurance, network policy, identity and authority
profiles, evidence window, state roots, and receipts. Operation disposition and
report verdict use separate closed vocabularies; a negative case passes only
when the expected refusal or reconciliation disposition is observed. Missing
evidence produces `incomplete`, not a weaker fabricated pass. Single-node local
operation never implies HA, quorum independence, TEE/cTEE, provider
non-learning, public settlement, cross-party matching, source rights, legal
compliance, or provider SLA.

`expected_report_verdict` in the matrix is the verdict the subject report must
emit for that test input. The outer execution-case verdict defaults to `pass`
only when the subject emits that expected verdict and the observed operation
matches the expected disposition. Therefore the missing-evidence self-test
passes only when the subject report says `incomplete`; it does not make every
claim intrinsically incomplete.

## Canonical matrix

The canonical target matrix is
[`sovereign-local-completeness-matrix.v1.json`](./sovereign-local-completeness-matrix.v1.json).
It supplies positive and adversarial cases for every requirement above.
Fixture rows are target evidence only. Current master has no
sovereign-local-completeness execution tier, so valid JSON and documentation
links do not establish a product pass.

## Required machine report

A future runner emits a report with at least:

```yaml
schema_version
matrix_ref
matrix_hash
claim_profile_id
claim_profile_hash
fixture_profile_ids
fixture_profile_hashes
overlay_ids
overlay_hashes
runner_version
subject_build_ref
subject_build_hash
daemon_api_version
public_contract_versions
agentgres_mode
runtime_operator
network_policy_hash
durability_profile_ref
custody_profile_ref
assurance_profile_ref
identity_profile_ref
authority_profile_refs
evidence_window
scenario_results:
  - execution_case_id
    scenario_id
    fixture_profile_ids
    fixture_profile_hashes
    overlay_ids
    overlay_hashes
    predecessor_report_ref_and_hash  # mandatory for overlay cases
    predecessor_evidence_ref_and_hash  # mandatory for overlay cases
    case_parameter_manifest_ref
    case_parameter_manifest_hash
    expected_operation_disposition
    observed_operation_disposition
    expected_report_verdict
    observed_report_verdict: pass | fail | incomplete
    case_verdict: pass | fail
    reason_codes
    evidence_refs
outbound_observation_refs
state_root_refs
authority_and_effect_receipt_refs
backup_restore_proof_refs
custody_writer_before_after
billing_summary_ref
declared_unavailable_capabilities
nonclaims
verdict: pass | fail | incomplete
```

The report is conformance evidence, not operational truth, authority, a
certification claim, or permission to execute.

## Open live gates and nonclaims

- isolated installer/client/daemon startup under enforced egress denial;
- a complete package-to-retirement bounded-System product journey;
- local exact-effect authority and zero-invoker negative proof;
- embedded/server Agentgres semantic parity and clean restore;
- offline receipt/root verification over authentic emitted evidence;
- managed attachment and detachment against real account/service owners;
- explicit usage/billing reconciliation with customer-borne cost exclusion;
- fenced placement/custody migration and failure injection; and
- aggregate runner/report validation against the canonical matrix.

Until those gates execute, the architecture defines the target claim and its
refusal boundary only. It does not claim a shipped self-hosted product,
standalone feature parity, multi-node availability, portable authority,
managed hosting, migration, public settlement, or network assurance.
