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
| `identity_preserving_migration` | managed optionality plus `identity_preserving_migration_overlay` |
| `multi_node_high_availability` | separate distributed-operability, membership, durability, and fencing evidence |
| `ioi_managed_hosting` | separate managed-provider, custody, availability, billing, and export evidence |

`embedded_single_operator_offline` uses one admitted node, embedded Agentgres,
local storage, deployment-local identity, a locally permitted authority
provider, and an admitted deterministic fixture or local-model route. Every
IOI-managed, marketplace, IOI Network, IOI L1, license, update, support,
telemetry, and external-model endpoint is blocked. It claims only its declared
single-node durability and failure domain.

`self_hosted_org_single_node` adds a normal customer-controlled server/headless
deployment, deployment-local or customer OIDC identity, customer storage, and
customer model/BYOK supply. It does not require HypervisorOS and does not claim
multi-node availability.

`managed_attach_detach_overlay` starts from a passing standalone fixture,
attaches exactly one named managed service, proves the service's data views,
leases, RuntimeAssignments, custody, charges, and receipts, then revokes or
detaches it. It is an overlay, not another deployment mode.

`identity_preserving_migration_overlay` is required only when a product claims
an identity-preserving placement or custody transition. It binds the applicable
Lifecycle Continuity decision and the complete fenced `HypervisorChangePlan`.
Multi-node HA and IOI-managed hosting remain separate conditional claims and
cannot be inferred from local completeness.

## Required runner surface

A future executable runner may provide test-only adapters with the following
semantic operations:

```yaml
configure_network_boundary
bootstrap_deployment
create_and_activate_system
execute_bounded_work
propose_and_admit_effect
query_state_root
crash_and_restart
export_backup
restore_backup
verify_exported_evidence
attach_managed_service
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
supported local client, daemon, and embedded Agentgres path without an
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
work path, an isolated attempt, independent deterministic verification, an
exact reviewed repository effect or typed refusal, receipts, an inspectable
state root, and the selected upgrade/recall/retirement lifecycle. Client
projections resolve the same owner refs and hashes. Missing verification cannot
be reported as completion.

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
path, and reproduces the declared state and receipt lineage. Tamper, gaps,
wrong roots, and missing predecessors fail closed. Restored grants,
revocation state, time state, or continuity floors cannot silently reactivate
or move currentness backward.

### SLC-07 — Public-contract semantic parity

The selected canonical fixture runs over embedded and server-backed Agentgres
postures and compares admitted operation commitments, stable identifiers,
hashes, public API semantics, receipts, and replay results. Capacity, SLO,
provider-native, and availability differences remain explicitly outside
semantic parity and retain honest durability labels.

### SLC-08 — Managed attachment without implicit transfer

Attaching an account or managed service alone changes no System identity,
package identity, authority, key, writer, canonical truth, custody,
institutional-learning boundary, network enrollment, or billing state.
Managed use begins only through separately reviewed service bindings, data
views, leases, RuntimeAssignments, authority, and receipts.

### SLC-09 — Detachment and dependency closure

After managed leases are revoked and managed endpoints are blocked, locally
satisfiable work and locally owned truth remain operable under their declared
authority, temporal, budget, partition, and fence profiles. Operations that
require the detached capability become typed blocked, unavailable, or
explicitly degraded. There is no account or license lockout and no
post-revocation remote execution.

### SLC-10 — Explicit fenced migration

Connection, discovery, sync, backup, or copying bytes is not migration. A
claimed migration freezes an authorized `HypervisorChangePlan`, verifies the
target import and readiness, quiesces and fences the source, admits one
cutover/writer epoch, preserves a rollback window, and records explicit source
retention, replica, archive, or teardown disposition. An interrupted cutover
retains source authority or enters typed blocked/reconciliation state; it
never produces two active writers. `system_id` is preserved only under an
applicable Lifecycle Continuity decision.

### SLC-11 — Economic boundary

Customer-borne local, BYO model, BYO tool, BYO provider, and customer-storage
supplier cost produces no managed-provider debit or generic pass-through Work
Credit charge. Attachment alone is not billable. An orchestration,
control-plane, support, or managed-service charge requires an explicit quote or
rate contract, actual named service use, and corresponding usage and billing
receipts.

### SLC-12 — Claim honesty

The report binds the exact tested build, fixtures, overlays, profile,
durability, network policy, authority posture, evidence window, state roots,
and receipts. Missing evidence produces `incomplete`, not a weaker fabricated
pass. Single-node local operation never implies HA, quorum independence,
TEE/cTEE, provider non-learning, public settlement, cross-party matching,
source rights, legal compliance, or provider SLA.

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
claim_profile_id
fixture_profile_ids
overlay_ids
subject_build_ref
subject_build_hash
daemon_api_version
agentgres_mode
runtime_operator
network_policy_hash
evidence_window
scenario_results:
  - scenario_id
    status: pass | fail | not_applicable
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
