# M17Q independent QUV review commission

Status: ready for the owner-authorized fresh automated reviewer

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
