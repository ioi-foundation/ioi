---
module_id: mechanism-gates
module_class: method
title: Status-free PG-* mechanism gate registry
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M0, M9]
legacy_id: proof-gates/mechanism-gate-registry.md
canon_owners:
  - docs/architecture/_meta/source-of-truth-map.md
  - docs/architecture/foundations/security-privacy-policy-invariants.md
  - docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md
  - docs/architecture/components/daemon-runtime/platform-operability.md
---

# Mechanism Gate Registry

The master activates these gates and owning work-item records carry their
applicability and closure status. This registry contains no live disposition,
current-state summary, Cut order, or completion claim. A passing reference test
does not satisfy a production-integration gate.

Applicability values in records are `required_now`, `conditional`, `later`,
or `out_of_scope`. Closing one gate never closes another. Each closure needs
owner integration, real final-invoker behavior where consequential, positive
and zero-invoker negative proof, retained evidence, and the owning record's
exact content-bound literal exit.

| Gate | Required production integration | Closure evidence shape |
| --- | --- | --- |
| PG-0.1 | Build the full `ImprovementCampaign` vertical: immutable governance/profile roots, Agenda/Campaign/Epoch/Exposure/Cutoff/Claim state, finite budgets, candidate/evaluator separation, negative-result retention, learning eligibility, OutcomeRoom/Foundry handoff, and target-owner proposal admission. | One target-order-0 campaign replayed from durable owner records, including adversarial exposure, evaluator, budget, and activation-separation proof. |
| PG-0.2 | Add route-level proof for anti-decomposition threshold, persisted impact assessment, exact waiver freshness, and the complete application-chain receipt. | Focused daemon verifier covers success, threshold crossing, stale base, forged/wrong-kind waiver, and receipt reconstruction. |
| PG-0.3 | Migrate persisted legacy underscore-scheme refs through explicit read aliases and canonical new writes. | Inventory reaches zero new legacy writes; each migrated family has read-old/write-new and collision fixtures. |
| PG-1.1 | Register remaining consequential pilot families, especially GoalRunProfile/GoalRun/GroundingLoop, RuntimeAssignment/HarnessInvocation, and the remaining physical-action envelope set. | Owner-approved schemas/invariants, positive/adversarial fixtures, generated projections, and runtime consumers for each promoted family. |
| PG-1.2 | Generate or mechanically verify owner-document reference blocks and adopt generated projections in additional SDK/CLI consumers where those consumers claim the contract. | Temporary regeneration produces no diff; owner prose links rather than redeclares wire fields; consumer parity tests pass. |
| PG-1.3 | Prove successor rollout, compatibility, migration, and hash impact for the first production breaking schema transition. | Mixed-version fixtures and deployed-reader/writer matrix reject undeclared downgrade or mutation. |
| PG-2.1 | Connect portable grants to real issuance, holder/audience identity, trust-root acquisition, key rotation, and bounded-staleness revocation discovery under the selected `TemporalVerificationProfile`. | Independent issuer and verifier processes pass rotation, stale/unknown key, revocation, audience, holder, uncertainty-overlap, reboot/restore, and outage probes without accepting caller-authored currentness. |
| PG-2.2 | Mount grant verification at every consequential production PEP rather than accepting copied authority fields. | Representative Agentgres, wallet, connector, storage, deployment, settlement, and actuator effects prove denial before invocation for invalid authority. |
| PG-2.3 | Emit ordinary and consequential receipts through Agentgres-owned append, scheduled signed checkpoints, and durable inclusion/consistency material. | Crash/restart and concurrent append preserve the exact checkpoint root and offline export verifies from production-emitted data. |
| PG-2.4 | Connect export verification to real signer/key/revocation discovery and bounded temporal verification windows, separating integrity, valid-as-of posture, and currentness. | Offline consumer starts without producer database access, resolves only declared immutable/trusted inputs, preserves authentic historical proof, and cannot turn an old checkpoint into current authority. |
| PG-2.5 | Add AIIP object/transport signatures, peer identity/version negotiation, and replay protection when the cross-domain transport is implemented. | Two independently governed systems exchange, reject replay/substitution, and verify the same portable proof. |
| PG-2.6 | Where a deployment explicitly selects a transparency profile, add witness/gossip or equivalent split-view detection and the selected public-log proof. | Conflicting checkpoints presented to independent observers are detected under that profile. |
| PG-3.1 | Carry exact labels and derivation closure estate-wide through ContextCells, summaries, model substitution, memory import/export, and every derived proposal/effect. | Cross-step fixtures cannot drop or weaken a restrictive parent and production owners supply labels instead of ambient defaults. |
| PG-3.2 | Normalize and guard MCP resources, prompts, elicitation, Tasks, and Apps; current coverage is limited to tool/list execution seams. | Each primitive has an owner mapping, untrusted-input posture, lease/authority behavior, and positive/zero-invoker negative tests. |
| PG-3.3 | Supply canonical browser IFC context from the production execution owner and enforce redirect, ambient request, response/download bytes, active/history/target-tab destinations, pointer-coordinate resolution, and general computer-use effects. | Browser/network canaries prove actual destination and returned bytes remain bound across redirects and alternate action paths. |
| PG-3.4 | Apply signed/replay-safe inbound and destination-aware outbound admission to connector families beyond the automation-webhook and current non-MCP HTTP seams. | Each promoted connector proves signature/time/nonce/idempotency plus denial immediately before its real driver. |
| PG-3.5 | Bind OutcomeRoom discussion, artifact-byte resolution, and durable label lookup/persistence without introducing a second truth owner. | Room/artifact/memory replay reconstructs the same label closure and cannot cite an unresolved or substituted label. |
| PG-3.6 | Build the institutional-learning-boundary conformance adapter and run its complete contract grade, then deployment grade for any product claim. | Deployed runner proves policy intersection, prohibited-provider/cross-tenant denial, Foundry lineage, export/import, revocation impact, and model-independence threshold. |
| PG-4A.1 | Build public System membership, writer-transition, failover, and promotion control APIs over owner-authorized records. | Authenticated control-plane tests cover admission, removal, promotion, stale requests, and restart. |
| PG-4A.2 | Connect automatic failure detection to an external continuity CAS/witness and the declared temporal profile, interval/uncertainty, lease, revocation, rollback-domain, and re-anchor rules; detection/evaluation must not mint promotion authority. | Partition, skew, delayed-revocation, reboot, and whole-state rollback tests show one admitted successor, a non-regressing outside-domain floor or fail-closed result, and no automatic-authority shortcut. |
| PG-4A.3 | Independently verify the active transition grant's signature, scope, expiry, revocation epoch, and issuer rather than comparing refs only. | Foreign, stale, revoked, widened, and copied-ref grants fail before transition or effect. |
| PG-4A.4 | Emit and reconcile `LostSuffixRecord` data, excluded-suffix custody, and rejoin readmission instead of implicit state merge. | Weaker recovery and rejoin fixtures preserve excluded facts and never silently accept a missing suffix. |
| PG-4A.5 | Mount owner-derived fence verification at every consequential Agentgres, wallet, connector, storage, deployment, settlement, and actuator PEP. | Estate matrix proves a deposed writer reaches zero real invokers after promotion. |
| PG-4A.6 | Deploy across independent failure domains and prove multi-node no-dual-writer behavior under partition, skew, restart, and witness loss. | Scheduled fault suite plus resource-side receipts demonstrates one effective writer or fail-closed state. |
| PG-4B.1 | Bind every GoalRun, GoalGroundingLoop, WorkRun, AutomationRun, HarnessInvocation, ContextCell, and external-handle owner write path to the shared lifecycle mechanism. Every work-owning create/attach/reattach/resume/rearm/replacement/reassignment/bound-change path must atomically validate exact ancestor and allocation heads, reject cycles and widened bounds, protect policy-required recovery/integration capacity, and commit per-dimension disjoint child reservations. | `live_owner_route_bindings` names each real adapter; route tests reconstruct the same phase/head and prove simultaneous siblings cannot inherit one remainder, stale rearm cannot reset ancestor bounds, live reassignment revalidates both ancestor chains and transfers rather than frees/duplicates responsibility and reservations, and non-authorizing dependency/evidence links confer no admission or authority. |
| PG-4B.2 | Verify owner authority/grant scope, expiry, and revocation immediately before lifecycle admission. | Wrong-owner, widened, stale, revoked, and copied-ref requests leave no transition record. |
| PG-4B.3 | Implement Agentgres-owned append and cross-process exact-head concurrency; do not introduce a daemon-local filesystem reference on this base. | Concurrent writers, crash/restart, and duplicate delivery converge without fork or lost accepted record. |
| PG-4B.4 | Emit owner events and completion receipts after durable commit, and execute cancellation drain/fence/lease-revoke/timeout/rollback/compensation/reconciliation plans with receipts. Preserve the affected authority and resource reservation until terminal/fenced proof or explicit ambiguity with funded reconciliation. | Cancellation and executor-loss fault matrices show every target terminal, fenced, or explicitly ambiguous with a funded reconciliation obligation; local process disappearance never releases the reservation or advances parent success. |
| PG-4B.5 | Automate archive selection, retention, pruning, and archive-only resume with fsync/rename/archive/snapshot/restore fault injection. | Pruned hot logs restore the identical object head, child index, idempotency map, and receipt lineage. |
| PG-4B.6 | Add mixed-version legal-table rollout/downgrade refusal and privacy filtering for future inspection APIs. | Old/new nodes agree or return typed upgrade-required; unauthorized subjects cannot enumerate private objects. |
| PG-4C.1 | Compile WorkRun risk/isolation requirements and bind the exact current backend capability. | Lower-boundary, stale-declaration, caller-downgrade, and substituted-backend requests refuse before launch. |
| PG-4C.2 | Enforce per-job identity, mounts, credentials, network, DNS, egress, and dependency-broker mediation. | Cross-job, host, metadata, daemon, peer, and unadmitted dependency paths deny while exact admitted paths remain receipted. |
| PG-4C.3 | Quarantine output and own terminal teardown. | Malicious archives refuse, admitted output is atomic, and evidence proves every resource removed or a durable cleanup obligation remains. |
| PG-4C.4 | Implement the selected machine/image/disk/network/access/snapshot lifecycle. | The exact Workstation matrix passes desired/observed, authority, receipts, recovery, and unsupported-operation refusal. |
| PG-4C.5 | Produce attached-estate host/cluster capability evidence. | The selected adapter discovers, reconciles, refuses unsupported operations, and detaches without external-resource or retained-truth loss. |
| PG-4C.6 | Run correlated isolation and virtualization faults. | Guest compromise, broker abuse, VMM loss, daemon restart, stale restore, output attack, and uncertain teardown converge to declared states. |
| PG-5.1 | Resolve and cryptographically verify referenced deployment, stream, timing, ODD, proof-test, authority, writer, and sensor evidence rather than validating supplied bindings only. | Independent evidence-store and revocation tests reject substituted, stale, unavailable, or unsigned evidence. |
| PG-5.2 | Implement the native graph scheduler and isolated `LocalControlSupervisor` monitor/switch/watchdog/recovery/e-stop boundary with live timing, assured-input, ODD-exit, and teleoperation behavior. | SIL/HIL or deployment evidence meets declared margins and produces safe responses under load, loss, and fault. |
| PG-5.3 | Mount the execution core immediately before real native or separately assured controller adapters, including redirect, bridge, standby, restart, alternate-controller, resource-group, and controller-identity paths. | CPAS-9 bypass probes prove every denial has zero actuator calls and every accepted call uses the exact fenced controller. |
| PG-5.4 | Persist physical idempotency, predecessor heads, and the full switch/proof-test/ODD/teleop/restart/handoff/command/segment/exception/e-stop/incident receipt family through Agentgres. | Restart/crash replay cannot reinvoke a completed command or lose an unknown effect; receipts verify offline. |
| PG-5.5 | Prove claimable E1–E3 levels across representative hardware, realtime profiles, fleet partition/rejoin, and sim-to-live promotion. | Deployment-specific conformance report prevents lower-level evidence from rendering a stronger claim. |
| PG-6A.1 | Resolve runtime receipt identities/quantities, signed provider price schedules, supplier statements, and every route-attempt/fallback invoice line. | Invoice reconciliation ties each charged unit to owner evidence and authentic supplier statements. |
| PG-6A.2 | Move billing append authority into Agentgres transactions and add public entitlement, purchase/top-up, processor, tax, and cash-ledger integration. | Cross-process concurrency and payment-processor fixtures prevent double hold/debit and distinguish accounting from money movement. |
| PG-6A.3 | Execute participant, verifier, broker, and supplier payouts plus refunds, chargebacks, and dispute-linked corrections. | Settlement receipts and processor reconciliation prove actual value movement without rewriting usage truth. |
| PG-6A.4 | Emit daemon billing events, signed checkpoints, offline audit export, and crash/compaction/backup/restore/mixed-version/reconciliation-outage tests. | Production ledger restores exact heads and exports a verifier-independent audit chain. |
| PG-6B.1 | Persist dispute case/resolution heads in Agentgres with cross-process exact-head concurrency and stale-adjudication refusal. | Concurrent adjudicators yield one admitted head; stale/foreign decisions leave no accepted record. |
| PG-6B.2 | Independently resolve evidence availability and adjudicator authority, implement appeal/supersession, and enforce legal-hold/retention/crypto-shredding windows. | Missing/stale evidence and unauthorized adjudicators trigger the declared default or denial; appeals preserve prior lineage. |
| PG-6B.3 | Hold and release/slash real challenger/respondent bonds and execute marketplace escrow refund/payout/remedy reconciliation. | Wallet/processor receipts conserve the exact bound asset-unit and reconcile both parties. |
| PG-6B.4 | Exchange bilateral AIIP dispute packets/receipts and, only for enrolled profiles, prove public-settlement inclusion/finality. | Independent peers verify the same case; local rails remain available when public settlement is not selected. |
| PG-6B.5 | Emit required dispute, bond-distribution, remedy, and escalation receipts plus offline proof export. | Receipt bundle distinguishes admitted allocation from executed value movement and verifies independently. |
| PG-6C.1 | Add real CPU/TEE/TPM/DICE/secure-element/GPU quote drivers, atomic nonce consumption, signature/certificate verification, endorsement/reference-value resolution, and live revocation. | Vendor-backed and negative quote suites bind exact workload/build/policy and reject replay, substitution, and stale evidence. |
| PG-6C.2 | Mint/revoke attestation-bound leases, schedule re-attestation, and supply structured evidence to actual `ioi-agent` startup/degraded-operation paths. | Evidence expiry or loss narrows/stops the exact workload according to policy without inheriting a stronger label. |
| PG-6C.3 | Run deployment fault injection for quote service, endorsement, revocation, lease, clock, and hardware-evidence loss. | Startup and ongoing operation remain deterministic under correlated assurance failures. |
| PG-6D.1 | Resolve authentic jurisdiction-pack, incident-clock, reporting, erasure, retention, legal-hold, and exception inputs. | Accountable-issuer signatures and receipts prove the exact version and source of each projection input. |
| PG-6D.2 | Connect regulator-notification/reporting clients, erasure/key-destruction effectors, replica/backup scope discovery, and legal-hold enforcement. | External acknowledgements and destructive verification receipts match the projected deadlines and scope. |
| PG-6D.3 | If a product needs a legal-conformity assertion, integrate a separately authorized accountable issuer; the generated evaluator remains `not_determined`. | Issuer-specific signed claim cites the projection and applicable legal review without changing evaluator output. |
| PG-7.1 | Produce authenticated, owner-rooted plane observations and temporal evaluations, then mount the existing operability admission immediately before real scheduler/effect invokers. | Missing/stale/forged evidence, indeterminate expiry overlap, lost continuity floor, or imported evaluation yields zero invoker calls for each affected operation class. |
| PG-7.2 | Schedule correlated failure injection across shared daemon, Agentgres, authority, storage, clock, provider, fleet, attestation, billing, and settlement failure domains. | Actual states and obligations match the checked fault matrix. |
| PG-7.3 | Restore checkpoints/backups through each plane's real persistence engine, reconcile retained/lost suffixes, and preserve or freshly re-establish every required owner-scoped temporal/key/revocation/checkpoint floor outside the restored rollback domain. | Restored state and proof roots match the declared checkpoint; a pre-revocation whole-VM restore reaches zero consequential invokers until fresh/outside-domain currentness is established, otherwise fails with explicit loss/unavailable records. |
| PG-7.4 | Distribute and revoke signing-key epochs across real signer/verifier processes. | Rotation has one active signer, preserves the verification window, and rejects stale/revoked epochs. |
| PG-7.5 | Exercise deployed mixed-version rollout, rollback, and typed upgrade requirements. | Consequential unknown fields are never guessed or lost through downgrade. |
| PG-7.6 | Reconcile production quote/usage/debit/refund with receipt/checkpoint truth after outage and replay. | Accounting, supplier, and proof heads converge or remain explicitly disputed. |
| PG-7.7 | Define and test capacity, saturation, backpressure, and load-shed behavior for every plane, including recursive child admission, reservation shrink/expiry/transfer, and protected verification/integration/recovery capacity. | Overload narrows availability without widening authority, oversubscribing one ancestor balance, starving required recovery, or converting unknown effects to success. |
| PG-7.8 | Run end-to-end observability canaries against telemetry and learning sinks. | Protected raw content never crosses a disallowed sink; allowed projections contain only governed refs/hashes. |

## Reusable adversarial proof shapes

| Boundary | Positive proof | Required negative proof |
| --- | --- | --- |
| Schema | All selected runtimes accept one golden object. | Missing condition, wrong enum, invalid ref, incompatible version. |
| Canonical hash | Independent runtimes reproduce the digest. | Type, version, domain, number, Unicode, or payload alteration. |
| Authority | A valid narrowed grant admits at the final PEP. | Widened child, wrong audience/holder, expired/revoked/stale grant; zero invoker calls. |
| Receipt export | Offline manifest/inclusion verifies. | Tamper, absent inclusion, inconsistent checkpoint, unknown signer. |
| Information flow | Admitted input reaches only an allowed destination. | Restrictive labels are dropped or untrusted input gains instruction authority. |
| Failover/fencing | A valid successor acts once. | Old-writer effect, stale read, missing CAS, skew or floor violation. |
| Work lifecycle | Retry/cancel/replay converges. | Duplicate effect, illegal transition, orphaned invocation/lease/reservation. |
| Embodied | The admitted non-live profile stays inside declared bounds. | Unassured input, late switch, ignored ODD exit, teleop loss, two writers. |
| Billing/dispute | Quote/hold/use/remedy reconcile. | Double debit, stale price, unauthorized adjudication, lost refund or bond. |
| Attestation | Fresh appraisal binds the exact workload. | Replayed nonce, changed build, stale result, self-declared hardware. |
| Recovery | Checkpoint restores the declared state/root. | Missing suffix silently accepted, schema guessed, or restored currentness inferred. |

Product authority remains local/domain policy plus the applicable authority
provider, including wallet.network where portable delegation or a designated
high-risk scope requires it. Unsigned review evidence cannot satisfy a PG gate
that requires product authority.
