# Asymptote Fault Tolerance Protocol Corpus

Status: internal protocol corpus index.
Authority: `docs/architecture/` and accepted ADRs are canonical; this file is private protocol corpus navigation only.
Migrated from: `docs/architecture/consensus/aft/` and `docs/consensus/aft/` standalone documentation roots.
Superseded by: canonical architecture docs or ADRs when conflicts arise.
Last alignment pass: 2026-09-03 (ADR 0048 clean break).

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
- [`specs/maximal_prior_art_comparison_2026-09-03.md`](./specs/maximal_prior_art_comparison_2026-09-03.md)
  — dated task-level comparison against authenticated/synchronous BA,
  asynchronous BA/RBC/ACS, DAG availability, data-availability sampling,
  consensus-powerful shared objects, and Geeq user validation.
- [`twin/`](./twin/) — completed in-session clean-room precedent, explicitly
  bounded to specification clarity and vector agreement.
