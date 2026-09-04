# Asymptote Fault Tolerance Protocol Corpus

Status: internal protocol corpus index.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file is private protocol corpus navigation only.
Migrated from: `docs/architecture/consensus/aft/` and `docs/consensus/aft/` standalone documentation roots.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-09-04 (M10 R5 qualification).

This directory holds Asymptote Fault Tolerance protocol material that is large
enough to remain as its own private corpus. The formal source and specs are
supporting protocol context; durable architecture conclusions must be promoted
to `docs/architecture/` or accepted ADRs before they become canonical. Generated
traces, TLC state dumps, and compiled paper outputs live under
[`internal-docs/formal/aft`](../../../formal/aft/).

- [`specs/`](./specs/) — protocol specs, theorem surfaces, and yellow paper source.
- [`IMPLEMENTATION_LEDGER.md`](./IMPLEMENTATION_LEDGER.md) — active M0–M18
  post-quantum assurance and maximal-consensus status, evidence, and claim
  gates.
- [`MAXIMAL_CONSENSUS_ACTION_PLAN.md`](./MAXIMAL_CONSENSUS_ACTION_PLAN.md) —
  gated M9–M18 program from the immutable PQ v1 review through the
  non-circular `f=n-1` viability test, end-to-end production implementation,
  and independent claim admission.
- [`AFT_MAXIMAL_E2E_GOAL_PROMPT.md`](./AFT_MAXIMAL_E2E_GOAL_PROMPT.md) —
  persistent execution prompt for the M9–M18 program, including external
  owner-action and theorem-impossibility stop rules.
- [`docs/decisions/0048`](../../../../docs/decisions/0048-make-aft-pq-v1-a-clean-break-and-isolate-hypervisor.md)
  — production-profile boundary: classic BFT plus mandatory hash-only
  asynchronous progress, externally rooted portable verification, and no
  legacy guardian/BLS/scalar/CLI admission.
- [`formal/`](./formal/) — TLA+ source, configs, proof source, and formal-model READMEs.
- [`RUNBOOKS.md`](./RUNBOOKS.md) — operational runbooks.
- [`OPERATIONAL_POLICY.md`](./OPERATIONAL_POLICY.md) — operational policy.
- [`packets/`](./packets/) — historical review and external-evidence packets.
- [`packets/M12-maximal-visibility-theorem-review.md`](./packets/M12-maximal-visibility-theorem-review.md)
  — owner commissioning packet for independent review of the role-switching
  lower-bound candidate.
- [`evidence/m12-r2-daybreak-review-2026-09-03.md`](./evidence/m12-r2-daybreak-review-2026-09-03.md)
  — attributable context-isolated automated R2 review, its
  `REPAIR_REQUIRED` findings, and the R3 response; governed by ADR 0049 and
  explicitly not represented as human peer review.
- [`evidence/m10-r3-daybreak-retest-2026-09-03.md`](./evidence/m10-r3-daybreak-retest-2026-09-03.md)
  — exact R3 automated retest: prior high findings and M10-006/007 closed,
  while M10-003 remains open on four-signer cold-restart reproducibility.
- [`evidence/m10-r4-signer-startup-local-evidence-2026-09-03.md`](./evidence/m10-r4-signer-startup-local-evidence-2026-09-03.md)
  — finite signer-startup repair and successful 1,098.02-second local
  height-5/restart/height-7 reproduction.
- [`packets/M10-r4-remediation-retest.md`](./packets/M10-r4-remediation-retest.md)
  — exact-tag independent retest commission for closing AFT-M10-003.
- [`evidence/m10-r4-daybreak-retest-2026-09-03.md`](./evidence/m10-r4-daybreak-retest-2026-09-03.md)
  — R4 automated independent retest: signer readiness passed, but post-restart
  height 7 did not complete within 240 seconds; AFT-M10-003 remains open.
- [`evidence/m10-r4-resource-isolated-reproduction-2026-09-04.md`](./evidence/m10-r4-resource-isolated-reproduction-2026-09-04.md)
  — exact R4 owner-side reproduction passed under resource isolation; retained
  beside the adverse independent result as evidence of harness sensitivity,
  not as an independent gate pass.
- [`evidence/m10-r5-daybreak-qualification-2026-09-04.md`](./evidence/m10-r5-daybreak-qualification-2026-09-04.md)
  — exact R5 automated independent qualification: all eight signer starts,
  fallback, metrics, cold restart, recovered H4, authenticated H6, and H7
  passed; closes AFT-M10-003 and M10 with explicit automated-review limits.
- [`evidence/m12-r3-daybreak-retest-2026-09-03.md`](./evidence/m12-r3-daybreak-retest-2026-09-03.md)
  — exact-candidate `UPHELD` retest closing byte-portable M12a as
  `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS`; automated, not human peer review and
  not a result about ADR 0050's interactive class.
- [`docs/decisions/0050`](../../../../docs/decisions/0050-split-aft-m12-offline-and-interactive-visibility.md)
  — owner decision retaining that result as byte-portable M12a while opening
  participant-interactive, known-synchronous QUV as non-portable M12b.
- [`specs/query_unanimity_verification.md`](./specs/query_unanimity_verification.md)
  — normative research specification and exact assumption boundary for
  `aft_quv_v0`; no production or consensus claim is created.
- [`specs/query_unanimity_theorems.md`](./specs/query_unanimity_theorems.md)
  — M13Q arbitrary-set theorem surface, matching lower bounds, and explicit
  distinction from classical exact-decision Byzantine agreement.
- [`specs/query_unanimity_end_to_end_theorems.md`](./specs/query_unanimity_end_to_end_theorems.md)
  — M14Q predecessor-bound ordering, durable/live-handoff recovery, and T10
  consequence-composition theorem surface.
- [`evidence/m12b-quv-r3-local-evidence-2026-09-03.md`](./evidence/m12b-quv-r3-local-evidence-2026-09-03.md)
  — corrected, reproducible explicit-time enumeration and its bounded scope.
- [`evidence/m12b-quv-r3-daybreak-review-2026-09-03.md`](./evidence/m12b-quv-r3-daybreak-review-2026-09-03.md)
  — exact-candidate automated `REPAIR_REQUIRED` review finding the cross-
  operation correct-witness gap and partly vacuous liveness counter.
- [`evidence/m12b-quv-r4-local-evidence-2026-09-03.md`](./evidence/m12b-quv-r4-local-evidence-2026-09-03.md)
  — repaired assumption boundary, non-vacuous liveness campaigns, multi-
  correct positive rows, and split-witness countermodel.
- [`evidence/m12b-quv-r4-daybreak-review-2026-09-03.md`](./evidence/m12b-quv-r4-daybreak-review-2026-09-03.md)
  — exact-tag automated `PASS_CONSTRUCTION`, closing both R3 findings and
  opening M13Q without admitting a consensus or production claim.
- [`evidence/m13q-quv-theorem-local-evidence-2026-09-03.md`](./evidence/m13q-quv-theorem-local-evidence-2026-09-03.md)
  — arbitrary-set TLAPS proof (75 obligations), theorem/lower-bound pairing,
  and the explicit non-classical task boundary that opens M14Q.
- [`evidence/m14q-quv-e2e-theorem-local-evidence-2026-09-03.md`](./evidence/m14q-quv-e2e-theorem-local-evidence-2026-09-03.md)
  — 16-obligation arbitrary-set ordering/consequence lift plus reproduced T10
  at-most-once resource boundary and live-handoff scope.
- [`evidence/m15q-quv-handoff-restart-ceremony-local-evidence-2026-09-04.md`](./evidence/m15q-quv-handoff-restart-ceremony-local-evidence-2026-09-04.md)
  — complete disjoint/overlapping-root process matrix, including pre-install
  restart, state-before-anchor crash recovery, rollback refusal, exact-gate
  restart, post-recovery progress, independently verified boundary QCs, and
  non-authorizing operator ceremony at code commit `ce34c31a9`; with the T10
  evidence below, M15Q is complete locally and awaits M17Q review.
- [`evidence/m15q-quv-executor-t10-local-evidence-2026-09-04.md`](./evidence/m15q-quv-executor-t10-local-evidence-2026-09-04.md)
  — finalized workload manifest through Agentgres, fresh executor-side live
  QUV, direct process-local continuation consumption, T10 claim-before-call,
  one durable PQ atomic mutation, and verified ML-DSA resource evidence at
  code commit `bd1e91a6d`.
- [`packets/M12b-quv-construction-review.md`](./packets/M12b-quv-construction-review.md)
  — immutable-candidate independent construction-review commission.
- [`packets/M10-M12-owner-commissioning-handoff-2026-09-03.md`](./packets/M10-M12-owner-commissioning-handoff-2026-09-03.md)
  — exact immutable refs, publication choices, reviewer assignment fields,
  returned-evidence requirements, and deterministic resume rules for the two
  owner-only independent reviews.
- [`packets/M10-public-independent-review-request.md`](./packets/M10-public-independent-review-request.md)
  and [`packets/M12-public-independent-theorem-review-request.md`](./packets/M12-public-independent-theorem-review-request.md)
  — public outreach texts for qualified independent reviewers, bound to the
  exact immutable candidates and explicit response requirements.
- [`.github/scripts/prepare_aft_review_bundles.sh`](../../../../../.github/scripts/prepare_aft_review_bundles.sh)
  — fail-closed private-transfer bundle builder that pins annotated tag
  objects, clone-checks both candidates, and emits a checksum manifest without
  publishing them.
- [`evidence/m10-m12-review-bundle-reproduction-2026-09-03.md`](./evidence/m10-m12-review-bundle-reproduction-2026-09-03.md)
  — two-run byte reproducibility, independent clone checks, transfer hashes,
  and negative target-refusal evidence for the private review packages.
- [`evidence/m10-m12-public-review-outreach-2026-09-03.md`](./evidence/m10-m12-public-review-outreach-2026-09-03.md)
  — remotely read-back candidate refs and public GitHub commissions
  [#357](https://github.com/ioi-foundation/ioi/issues/357) and
  [#358](https://github.com/ioi-foundation/ioi/issues/358), explicitly still
  awaiting qualified reviewer assignment and reports.
- [`specs/maximal_prior_art_comparison_2026-09-03.md`](./specs/maximal_prior_art_comparison_2026-09-03.md)
  — dated task-level comparison against authenticated/synchronous BA,
  asynchronous BA/RBC/ACS, DAG availability, data-availability sampling,
  consensus-powerful shared objects, and Geeq user validation.
- [`twin/`](./twin/) — completed in-session clean-room precedent, explicitly
  bounded to specification clarity and vector agreement.
