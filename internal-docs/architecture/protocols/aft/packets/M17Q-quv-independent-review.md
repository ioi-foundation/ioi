# M17Q independent QUV review commission

Status: R1 `REPAIR_REQUIRED`; R2 candidate in preparation (2026-09-06). The R2
commission below becomes effective only when the annotated R2 tag named in
"Immutable subject (R2)" exists and its clean full M16Q run is retained.

## Immutable subject (R2)

- Proposed annotated tag: `aft-quv-v0-m17q-candidate-r2-2026-09-06`
  (created only after the clean full M16Q R2 run passes on the exact commit).
- The reviewer records the resolved tag object and peeled commit before work.
- Review only a clean disposable clone at the tag; do not read the
  commissioning checkout and do not accept uncommitted files.

## R2 delta the reviewer must inspect in addition to the R1 list

- Canonical conflict identity and expected head:
  `crates/consensus/src/aft/query_unanimity.rs` (`QuvConflictSlotV0`,
  `process_push_with_byte_limit`, `check_expected_slot`),
  `crates/consensus/src/aft/query_unanimity/head.rs`, `member_delta.rs`.
- Authenticated schema-9 journal and schema-3 handoff custody:
  `crates/consensus/src/aft/query_unanimity/journal.rs`, `journal/*.rs`,
  `handoff_reservation.rs`; spec `specs/query_unanimity_journal.md`.
- Deadline closure at observation, finalization and audit verification;
  runtime late-wake finalization: `crates/validator/src/standard/orchestration/quv.rs`
  (`finalize_operation_at_deadline`), `quv/dispatch.rs`.
- Rooted policy v8 (`push_admission`, claim-index storage charge,
  `WAITING_PER_PRINCIPAL`): `crates/types/src/config/mod.rs`,
  `crates/types/src/app/{query_unanimity,consequence}.rs`, `quv_policy_root`.
- Executor admission and fairness bounds: `quv/admission.rs`.
- Stable-key claim index and claim-time fence/continuation checks:
  `crates/agentgres/src/consequence.rs`, `consequence/claim_index.rs`,
  `consequence/receipt_reservation.rs`, both executor entries in
  `crates/validator/src/standard/orchestration/{mod,grpc_public}.rs`.
- PQ carrier provisional enrollment, loss recovery, deferred push ACK/NACK and
  stale-lane handling: `crates/networking/src/libp2p/{pq_channel,swarm,sync,types}.rs`,
  `crates/validator/src/standard/orchestration/{events,peer_management,sync}.rs`.
- Composed transition model and its countermodels:
  `formal/maximal_visibility/QuvEndToEndRefinement.tla` and cfgs, registered in
  `.github/scripts/run_aft_formal_checks.sh`.
- Process fixtures: `crates/cli/tests/aft_e2e.rs`,
  `crates/cli/tests/aft_e2e_parts/{quv_readiness,quv_flood}.rs`, evidence
  checkers under `.github/scripts/check_aft_*.py`.
- R2 remediation evidence: `evidence/m17q-r2-*-2026-09-06/` (scoped, dirty-tree
  development evidence; only the clean M16Q run on the tagged commit is
  qualification evidence).

The reviewer must re-adjudicate every stable identifier `QUV-M17Q-001..013`
explicitly (closed / repaired-but-unqualified / open), and may add new
identifiers `QUV-M17Q-014+`.

## R1 record (retained)

R1 evidence is retained unchanged in
`../evidence/m17q-r1-import-2026-09-04/`. The report records 13 critical/high
findings and contains unresolved result placeholders; the available reproduction
is incomplete. The R1 tag below remains the historical review subject. Do not
reuse it as a repaired candidate or treat this packet as R2 admission.

## Immutable subject

- Proposed annotated tag: `aft-quv-v0-m17q-candidate-r1-2026-09-04`
- The reviewer must record the resolved tag object and peeled commit before
  beginning work.
- Review only a clean disposable clone checked out at the tag. Do not read or
  modify the commissioning checkout and do not accept uncommitted files.

## Reviewer and independence

Use a fresh `gpt-daybreak-blue-latest` reviewer that did not implement this
candidate. Report model identity, review start/end time, clone path, resolved
tag and commit, worktree status, and any prior exposure or conflict. This is an
automated independent review, not human peer review, certification, or an
external institutional audit.

## Fixed claim under review

The candidate claims only this separately named interactive result:

> One reachable correct configured member out of n suffices for online
> conflict-qualified accepted-value non-conflict and no-conflict singleton
> progress when every relying executor performs fresh push/write-before-reply
> verification against every configured member within a rooted known-
> synchronous end-to-end deadline, and correct-member conflict state is atomic,
> durable, monotone, correctly scoped, and non-rollback.

The claim includes the implemented predecessor/order/state and T10
externalization composition under their stated assumptions. It does not claim
portable/offline finality, asynchronous progress, exact-decision Byzantine
agreement, classical Byzantine consensus, or a transferable finality
certificate. `portable_final_receipt=false`. M12a and original M13-M18 remain
unchanged and blocked.

## Required source review

Read the accepted ADRs, action plan, implementation ledger, QUV specifications,
theorem and composition specifications, TLA+ modules and proofs, Rust protocol
and executor paths, network/PQ boundaries, reconfiguration/recovery code,
process fixtures, the M16Q runner, and every retained M16Q command/log/hash.
Trace each theorem assumption to an enforcement point or explicit deployment
obligation. Trace every authorizing byte and process-local continuation from
input through irreversible execution.

At minimum inspect:

- `docs/decisions/0048-make-aft-pq-v1-a-clean-break-and-isolate-hypervisor.md`
- `docs/decisions/0050-split-aft-m12-offline-and-interactive-visibility.md`
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_verification.md`
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_theorems.md`
- `internal-docs/architecture/protocols/aft/specs/query_unanimity_end_to_end_theorems.md`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/QueryUnanimityProof.tla`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/QueryUnanimityCompositionProof.tla`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_model_r4.py`
- `internal-docs/architecture/protocols/aft/formal/maximal_visibility/quv_timed_results_r4.json`
- `.github/scripts/run_aft_m16q_qualification.sh`
- `internal-docs/architecture/protocols/aft/evidence/m16q-quv-qualification-2026-09-04.md`
- `internal-docs/architecture/protocols/aft/evidence/m16q-runs/20260904T204403Z-ab8d2e58103a/`

If a named path moved, find the canonical equivalent and record the mapping.

## Mandatory reproduction

From the clean immutable checkout run:

```sh
bash .github/scripts/run_aft_m16q_qualification.sh
```

Preserve the new complete run directory and compare phase dispositions,
environment, source hashes, process observations, timing envelope, and failures
with the retained commissioning run. A partial/quick run cannot close M17Q.

## Independent executable twin

Create a spec-only executable twin without importing or translating production
QUV decision code. Derive it from the written state machine and theorem
assumptions. Cover arbitrary correct-member placement for bounded n, concurrent
opposing candidates, independent operation order, Byzantine omission and valid
conflict injection, deadline edges and skew, write/reply/crash order,
durability/rollback, stale and cross-context replay, membership changes,
executor revalidation, and unrelated conflict domains.

Include negative mutations for at least: absent correct reply, one-way-only
timing, reply-before-durable, rollback, split write/read atomicity, missing
domain/slot/root/configuration/candidate binding, cached or portable acceptance,
and skipped executor-side QUV. Report explored state counts and minimized traces
for every conflict or liveness failure. Do not treat bounded exploration as an
arbitrary-n proof.

## Required adversarial questions

1. Does every accepted operation include every correct member's timely reply,
   or can queueing, routing, identity, membership, or clock behavior exclude it?
2. Is persistence complete before signing/replying across process and storage
   crash boundaries, including directory and rollback-anchor durability?
3. Can two correct members serialize concurrent candidates in opposite orders
   and still permit conflicting accepts?
4. Are replies bound to the exact root, configuration, domain, instance, slot,
   candidate, operation/session, and timing context needed by the proof?
5. Can stale replies, alternate encodings, source substitution, replay, or a
   precomputed response authorize another operation?
6. Can Byzantine traffic starve or delay a correct request while the verifier
   still believes the rooted deadline holds?
7. Does every irreversible executor itself perform fresh QUV and directly
   consume only the process-local continuation?
8. Can an audit transcript, RPC result, receipt, cached assertion, operator,
   ceremony artifact, boundary QC, or predecessor proof become authority?
9. Does crash recovery recreate authority, skip QUV, fork monotone state, or
   revive retired membership/key material?
10. Are disjoint and overlapping reconfiguration roots safe at the exact
    certified boundary, including old-root retirement and long-range bootstrap?
11. Can a conflict or withholder in one domain block or authorize another?
12. Is the T10 stable-key claim-before-call and ambiguity reconciliation path
    actually at-most-once under all modeled crashes?
13. Does any BLS, VDF, classic-BFT, legacy, fallback, non-PQ channel, or
    Hypervisor dependency enter the QUV theorem-bearing authorization path?
14. Do code, proof, model, test, schema, ledger, and public wording agree on
    timing, reachability, durability, liveness, validity, PQ, and portability?
15. Is any statement broader than the evidence, especially the words
    consensus, finality, unconditional, asynchronous, portable, or receipt?

## Deliverable and disposition

Return a committed Markdown report plus the twin source, raw twin results,
complete clean reproduction logs, hashes, environment, and exact commands.
Use stable finding identifiers `QUV-M17Q-NNN`, severity, affected paths/lines,
reproduction, exploit or proof trace, violated claim/assumption, and concrete
remediation. Separate proof defects, implementation defects, test/evidence
gaps, deployment assumptions, and wording defects.

Choose exactly one disposition:

- `PASS`: full reproduction passed, the independent twin supports the exact
  claim and required negative mutations, and no critical/high finding remains.
- `REPAIR_REQUIRED`: the construction may survive, but any required evidence
  is missing or a remediable finding remains.
- `REJECT`: a reproduced counterexample or proof defect defeats the fixed
  interactive target under its declared assumptions.

M17Q closes only for the exact reviewed commit with no unresolved critical or
high finding. Any code, proof, model, test, or claim change requires a new
candidate and fresh review. Reviewer silence is never evidence.

### 2026-09-05 — R1 journal remediation status

Production member storage is now schema 7, with immutable authenticated typed records and external anchor commit before memory publication. The preceding schema-6 format is refused without migration; handoff remains schema 3. The scoped unit/runtime/benchmark and three-slot/restart process qualification passes, with exact four-member participation and strict release/readiness checks. R1 remediation remains the critical path: rooted lifetime/rate/storage/fairness profiles, safe retention/compaction and full transition refinement are still incomplete. No whole critical/high R1 finding, clean M16Q R2, fresh M17Q review or M18Q admission is closed by this result. See the schema-7 journal specification and `evidence/m17q-r1-journal-production-2026-09-05` for the exact source subset, raw checks, intermediate failures and scoped disposition.

### Current schema-8 continuation

The latest source adds policy-bound preparation replay, explicit one-preparation-waiter admission and two-pass streaming recovery. The historical schema-7 process campaign is not evidence for these changes. See `../evidence/m17q-r1-rooted-replay-2026-09-05/` and the current fault/property closure matrix. R2 commissioning remains gated on the complete resource/refinement and qualification obligations; do not review or admit the dirty working tree as an immutable candidate.


### Schema-9 finite-profile disposition (2026-09-05)

The current production policy commits a finite slot horizon, first-two conflict
representation, candidate byte cap and encoded record/lifetime budgets.
Historical queries preserve retained conflict knowledge after the forward slot
horizon is exhausted. Enrollment rejects insufficient encoded lifetime headroom
before creating files. The abstract summary and lifetime proofs are mandatory
formal gates, including the event-reuse negative control.

This remains R1 remediation. Encoded accounting does not reserve physical disk
space or discharge transport/authentication, fair service, recovery duration,
cross-configuration retention or full transition refinement. The integrated
Q-A3/Q-A5/Q-A9 obligations are open. See the current journal specification and
single fault/property closure matrix. No whole finding, clean R2, independent
review or M18Q claim is admitted by these component results.


Current outbox implementation uses immutable entry files and the AFTPQI03 index,
with validated v2 conversion during startup. See the protocol specification and
`../evidence/m17q-r1-indexed-outbox-2026-09-05/`. These are scoped dirty-tree checks;
clean R2 and candidate freezing remain required before commissioning fresh review.
All 13 whole findings remain OPEN; review must inspect the new commit/recovery,
cleanup and physical/service profile rather than inheriting older outbox evidence.


The current R1 working tree now uses AFTPQI04 allocated index envelopes around
the logical v2 queue index. The older AFTPQI03 description is historical. Review
must inspect the Linux allocation/exchange startup requirement, checksum scope,
pre-directory-sync crash alternatives, no inactive-image recovery fallback and
remaining payload/metadata/memory/service assumptions. Scoped evidence lives at
`evidence/m17q-r1-index-reservation-2026-09-05/`; this does not commission review
or qualify a candidate. Clean R2 and immutable freezing remain prerequisites.


The working storage variant has advanced to AFTPQI05 inside AFTPQI04 envelopes,
with AFTPQA01 QUV arenas. Review the protected old-slot/new-slot mapping, migration
crash outcomes, retired-file fallback refusal and narrow normal-capacity cleanup
classification. Final scoped evidence is
`evidence/m17q-r1-payload-arena-2026-09-06/normal-capacity/`. This does not commission
review; clean R2 and candidate freezing still precede fresh independent review.


Current R1 work adds a root-derived member record reservation pool with unchanged
canonical authenticated record bytes. Inspect its physical-versus-encoded charges,
pre-continuation checks, inode transfer and recovery ordering. Current scoped
inputs are in `evidence/m17q-r1-member-reservation-2026-09-06/allocation-charge/`;
the parent benchmark is older-source evidence. The anchor-reservation draft is
not linked or tested. Clean R2 and immutable candidate freezing still precede
commissioning fresh independent review.


The anchor draft is now integrated; its scoped 81-core/21-runtime and formal/
syscall evidence is `evidence/m17q-r1-anchor-reservation-2026-09-06/`. The later
handoff final-fence/reachable-recovery revision has 83-core/21-runtime evidence
at `evidence/m17q-r1-handoff-final-fence-2026-09-06/`. Both are historical selected
dirty-source bindings as storage remediation continues. No review is commissioned;
clean full R2 and immutable freezing remain required. All 13 whole findings OPEN.


The handoff path now reserves its exact state/anchor data before its own live
operation; inspect preparation identity, no-authority semantics, final capacity/
continuation fence, pending-state recovery and unchanged installed raw format.
Scoped evidence: `evidence/m17q-r1-handoff-reservation-2026-09-06/`. This updates
review inputs only; clean R2 and immutable freezing still precede commissioning.


Consequence storage work now enforces the manifest-derived trace lifetime and
the fixed PQ adapter's canonical evidence/record bounds, preserves receipt hashes
through a borrowed streaming hash view, and derives a named-profile encoded
receipt ceiling. Inspect `evidence/m17q-r1-consequence-trace-bound-2026-09-06/`
with its per-revision source bindings. This is not physical reservation or full
refinement, and does not commission review. Clean R2/freezing still come first.

R1 endpoint input change (2026-09-06): the named Linux PQ endpoint now reserves
record data before QUV, validates active signed records, and publishes the same
inode without live allocation. The new syscall gate and regressions are scoped
repair evidence. Complete receipt/global resource/service/refinement obligations
and clean R2 are still prerequisites; no fresh review has been commissioned.

R1 receipt input change (2026-09-06): AFTCR001 wraps the unchanged consequence
receipt object in two initialized, allocated files. The scoped receipt gate
checks four live replacement phases and rejects removed initialization/sync and
live truncation controls. Failed payload-equals-physical allocation prototypes
are retained. Full R2/global profile/refinement are still prerequisites; this
is neither an independent review nor release admission.

R1 locator change: committed-manifest lookup now uses a rebuilt locator index and
revalidates the selected committed block/root/identity on every call. The fold
proof, restart/duplicate/corruption and one-selected-read tests are scoped repair
evidence only. Full R2 remains required before commissioning fresh review.

### Effect preparation guard (2026-09-06)

Both executor entry points compare exact manifest binding and run rooted
signature, membership, policy and expected-head preflight before per-effect
allocation. Authorized/Claimed retries require preflight; non-executable
readmission skips it but still rederives committed authorization. Preparation
creates no live grant. Global lock files may precede this guard.

`QuvEffectPreparationProof` proves a conditional guard kernel: nine TLAPS
obligations and 25 states pass. **Assumes:** correct committed admission and
rooted validator predicates, exclusive nonrollback custody, and OwnLive denotes
the executor's own successful exact-root QUV. Complete transition composition
and physical/fair service bounds remain open. SkipBinding/SkipPreflight violate
PreparationChecked; PreparedBearer violates GrantIsOwn.

Evidence: `evidence/m17q-r1-effect-preflight-2026-09-06/` (selected worktree
source, not immutable qualification). 31 consequence, 15 runtime-finality,
21 QUV runtime and two executor tests, CLI compile, formatting and formal checks
pass. Three production omission controls fail as intended; source is restored.
The new sole-correct-placement process negative requires the precise signature
refusal and unchanged per-effect bytes before valid execution; compiled only.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED.

### Continuation admission ownership (2026-09-06)

The runtime completion channel carries a non-cloneable admitted continuation.
Its admission share survives delivery, post-query committed revalidation and
the synchronous T10 consequence call or durable successor install. A cancelled
observer cannot release a started blocking worker's share. Undeliverable or
unused continuations release ownership when dropped. Only the own-live core
grant authorizes execution; the admission wrapper supplies no authority.

`QuvContinuationAdmissionProof` proves the conditional ownership kernel (nine
TLAPS obligations, eight states). Early delivery release and worker-observation
cancellation countermodels violate Ownership. **Assumes:** every relying call
keeps the wrapper through its synchronous transition and every started worker
owns it until return/unwind. Mapping: completion send is Deliver, consuming
callback is Start/Finish, failed delivery is CancelDelivery, dropped join handle
is CancelObservation. This is not a fairness or worst-case service proof;
pre-allocation admission and aggregate physical bounds still need integration.

Scoped evidence: `evidence/m17q-r1-continuation-admission-2026-09-06/`. Fifteen
runtime-finality, 22 QUV runtime and two executor tests, CLI compile, formatting,
syntax and formal checks pass. The early-release production control fails as
intended; original source is restored. Process campaign is running; it has not
been claimed passing. All whole findings remain OPEN; no clean R2 or M18Q
admission.

2026-09-06 continuation/preparation process outcome: the final scoped campaign
`evidence/m17q-r1-continuation-admission-2026-09-06/process-recovery/admission-diagnostic/`
passes four explicit initial admissions, four signature/storage negatives, all
sole-correct placements, exact recovery/replay, concurrent workload, typed
conflict/non-mutation, unrelated execution and expired-result retrieval. The
strict source-bound checker passes with retained component service/release
checks and 4053.866 ms observed four-way overlap. Sole replies are
288/298/300/297 ms; saturation maximum 2586 ms, all within 4000 ms. Ancestor
startup/unadmitted failures remain retained. Initial admission is now explicitly
proved by the probe before isolation; earlier unadmitted-state root cause is
not established by this later pass. Full R2 and every whole finding remain open.

### Receipt leaf custody guards (2026-09-06)

Directory-entry absence now uses symlink_metadata: dangling active links and
metadata errors cannot become fresh authorization. On Unix, initial receipt
staging and the consequence lock use the existing no-follow, regular-file,
single-link guard before truncation or locking. Existing generic non-Unix
adapters remain outside the Linux reserved profile.

**Assumes:** exclusive nonrollback custody of the store and its parent namespace;
ordinary Unix no-follow/open/lock semantics. These leaf checks do not establish
parent-directory custody, adversarial namespace race protection, aggregate
physical resources, or full transition refinement. Invalid active state maps
to refusal, never the Absent case of QuvEffectPreparation. The existing reserved
receipt proof's private-file antecedent remains conditional on these OS/custody
assumptions. No stored bytes create live authority.

Evidence: `evidence/m17q-r1-receipt-custody-2026-09-06/with-lock/`. Thirty-three
consequence, 15 runtime-finality, 22 QUV runtime and two executor tests, CLI
compile, formatting, formal guard checks and receipt syscall controls pass.
Original failing dangling-active/lock-alias regressions are retained. Removing
existence, staging, or lock validation produces the expected test failure;
original source is restored. Previous process evidence predates this change.
All whole findings remain OPEN; R2 unqualified; M18Q NOT_ADMITTED.


2026-09-06 queued preparation update: executable effect and handoff allocation
now runs under operation admission, with store release before waiting and
committed admission rederivation afterward. Conditional proof, deadline/ownership
regression and inspection-write negative evidence are indexed in
`evidence/m17q-r1-queued-preparation-2026-09-06/`. See the specification's Queued
preparation refinement Assumes and limitations. Terminal/reconciliation fairness,
aggregate resource/retention bounds and complete refinement remain outstanding.
All 13 whole findings remain OPEN; R2 unqualified, M17Q REPAIR_REQUIRED,
M18Q NOT_ADMITTED. This supersedes no prior failed evidence or immutable-source
requirements.


2026-09-06 terminal readmission: final outcomes skip receipt-pair preparation
while retaining committed validation and exact resource lookup; ambiguous states
retain preparation for reconciliation. Scoped tests, the extended preparation
proof/countermodel and restored production omission are retained in
`evidence/m17q-r1-terminal-readonly-2026-09-06/`. See the protocol/end-to-end
Assumes and limitations. The mandatory reservation-test namespace is corrected.
No whole finding closure, R2 qualification, M17Q acceptance or M18Q admission.


2026-09-06 receipt admission/profile v7: both executor entries serialize initial,
terminal and live-owner receipt access through bounded FIFO admission, release
storage before operation/network waits, and rederive after queueing. Protected
owner capacity is separate from current and historical result waiters. Queue
coefficients enter policy-root v7; current schema formats are unchanged and old
provisioning roots cannot silently migrate. Conditional mapping, service debt
and exact root vector are in the protocol/end-to-end specification. Evidence:
`evidence/m17q-r1-receipt-admission-2026-09-06/`; collector status is authoritative.
All whole findings remain OPEN and M15Q-M18Q remain unadmitted.


2026-09-06 v7 receipt pressure/restart outcome: the source-bound campaign in
`evidence/m17q-r1-receipt-admission-2026-09-06/pressure-process/` passes after
1068.80 seconds including release-node compilation and provisioning. Three
consecutive slots include exactly four expected correct members, with maximum
valid replies 394/646/495 ms against the unchanged 4000-ms envelope. An unrelated
same-executor effect completes while 120 exact parent-result replays run across
5773 ms; the child remains in its required readiness wait. Restart before slot
three preserves exact terminal recovery and the required positive child wait.
The strict checker passes with unchanged captured source hashes and complete
service-release evidence. A broader source archive, toolchain, command,
environment overrides and component hashes are retained. This is finite scoped
working-tree evidence, not clean R2 or a worst-case resource/service proof. All
whole R1 findings remain OPEN; M17Q REPAIR_REQUIRED; M18Q NOT_ADMITTED.


Post-query model extension: QuvQueuedEffectPreparation now exposes receipt
reopening and finality-lock acquisition separately, allowing context changes
while the receipt lock is held before finality is acquired. Nine obligations and
four countermodels pass, including removed final revalidation producing an
unauthorized-call trace. Evidence: receipt-admission campaign's
`post-query-model/`. Production Rust is unchanged from the passing pressure run;
this later formal/harness source is separately bound. Validation, custody,
continuation timing and full service/refinement antecedents remain conditional.


2026-09-06 candidate decode boundary: the public effect entry uses
`decode_quv_candidate`, which checks the existing rooted 4096-byte cap before
canonical SCALE decoding. Exact-fit input parses; oversized canonical and
undecodable inputs return the capacity error; empty input retains codec refusal.
Parsing grants no authority. Removing the pre-decode guard fails the existing
mandatory capacity regression, and exact source is restored. Evidence:
`evidence/m17q-r1-candidate-decode-2026-09-06/` (one capacity regression, two
executor regressions, CLI compilation, format and syntax pass on unchanged
selected sources). The earlier pressure process predates this production change.

Proof obligation: this establishes the input-length antecedent at this decoder
entry; it does not establish SCALE heap/allocation amplification, already decoded
protobuf storage, total in-flight requests, authentication service, or the full
resource/transition refinement. Those antecedents remain OPEN under Q-A3/Q-A9.
The policy-root value is unchanged because the capacity was already rooted.
All whole findings remain OPEN; no clean R2, independent acceptance or M18Q
admission follows.

Registry identity evidence added at `evidence/m17q-r1-registry-identity-2026-09-06/`.
Review the v2 completeness/atomicity antecedents and explicit refusal of unindexed
legacy state. The guarded duplicate identity no longer invalidates a prior
admission. Scoped positives, restored omissions and conditional formal results
pass; the initial compiler ENOSPC and successful same-source retry are both
retained. This repair postdates the last pressure process and remains unqualified
for R2. All whole findings stay OPEN; no fresh review has been invoked.

Additional source-bound repair evidence:
`evidence/m17q-r1-overlay-scan-2026-09-06/`. Inspect backing error propagation
through the state overlay into v2 registry bootstrap, including the original
failing service regression and conditional proof. M16Q now schedules the complete
automated formal corpus; partial mode success no longer substitutes for it.
The coverage correction has syntax/census evidence only, not a full R2 run.
Fresh review is still gated on integrated qualification and immutable freezing.
