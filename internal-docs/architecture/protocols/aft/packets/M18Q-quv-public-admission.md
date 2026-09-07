# M18Q — QUV public admission and release packet

Status: **NOT ADMITTED** (draft prepared 2026-09-07 while the clean M16Q R2 run
executes; every `PENDING` field is filled only from the retained R2 run and the
fresh independent M17Q review of the exact same commit). This packet admits a
claim only when Section 8 is complete and no critical or high finding remains
unresolved on the reviewed candidate. It authorizes no public push, deployment,
paid engagement, disclosure or publication; those remain owner actions.

## 1. Immutable candidate

- Annotated tag: `aft-quv-v0-m17q-candidate-r2-2026-09-07` (created by
  `.github/scripts/freeze_aft_quv_candidate.sh` on the commit that adds the
  retained run; the tag object and peeled commit below are filled in the
  follow-up manifest commit, which does not alter the candidate)
- Tag object: PENDING
- Peeled commit: PENDING (must equal the commit that adds the retained run)
- Retained clean run: `../evidence/m16q-runs/20260907T152920Z-9ce911fe798b/`
  (candidate code commit `9ce911fe7`; result PASS, 63 phases, 7217 s, clean non-quick tree)
- Independent review of that exact commit: PENDING (report path, model
  identity, disposition, independence disclosure)

## 2. The exact claim admitted

Only this separately named interactive result is admitted:

> One reachable correct configured member out of n suffices for online
> conflict-qualified accepted-value non-conflict and no-conflict singleton
> progress when every relying executor performs fresh push/write-before-reply
> verification against every configured member within a rooted known-synchronous
> end-to-end deadline, and correct-member conflict state is atomic, durable,
> monotone, correctly scoped, and non-rollback.

Assumes Q-A1 through Q-A10 exactly as stated in
`../specs/query_unanimity_verification.md` Section 2, the fixed rooted
configuration and slot, at least one correct member, static faults, and the
composition premises Q-EA1 through Q-EA8 of
`../specs/query_unanimity_end_to_end_theorems.md`.

Not admitted, and not to be printed: portable or offline finality; asynchronous
or eventually-synchronous safety before an independently established bound is
active; exact-decision Byzantine agreement; classical Byzantine consensus; a
transferable finality certificate; inclusion or effect liveness for any input
that is refused, aborted, vetoed, frozen or equivocated; fairness among
competing valid submissions. `portable_final_receipt=false` is mandatory.
M12a remains `PROVED_IMPOSSIBLE_UNDER_CONSTRAINTS` and original M13–M18 remain
blocked.

## 3. Separation of guarantees

| Guarantee | Statement | Where proved / qualified |
|---|---|---|
| Accepted-value non-conflict (Q-T1, Q-S1) | No two honest executor operations accept different candidates for one rooted conflict-domain slot | `QueryUnanimityProof.tla` (arbitrary-set TLAPS), R4 timed model, composed transition model, process campaigns |
| Decision termination (Q-T3) | Every honest operation ends with a typed outcome after at most its rooted interval plus service budget | Runtime service budgets; late replies discarded; process campaigns |
| Inclusion | Not a QUV guarantee | — |
| Effect authorization (Q-E2, Q-EA4) | An irreversible effect executes only as the continuation of the executor's own live operation against the currently committed admission | Executor entries, claim-time fences, claim index, T10 kernels, process campaigns |
| Externalization at most once (Q-E3, T10) | Claim before call on the stable key; ambiguous calls reconcile by lookup only | `AtMostOnceExternalization.tla`, claim index, consequence tests |
| Fairness | Not claimed; bounded queued waiters per domain and per principal only | Admission tests; measured costs in Section 5 |

## 4. Retained lower bound and boundary

M12a: portable byte-only authorization with copyable participant state cannot
combine non-conflict and solo non-Abort progress at f = n−1 (tag
`aft-maximal-visibility-lower-bound-candidate-r3-2026-09-03`, `UPHELD_WITHIN_SCOPE`).
M12b (ADR 0050): QUV is interactive and known-synchronous; Q-A3 is a safety
assumption; no timeout, silence, cached transcript, relay, notary, TEE or
honest-majority custody creates authority; no downgrade from PQ v1.

## 5. Explicit costs (measured on the qualification host; confirmed by the retained R2 run `20260907T152920Z-9ce911fe798b`: single-correct 62 budgeted releases max 9.34 s, flood 58 max 10.80 s with reply maxima 2389/1572/424 ms, readiness reply maxima 1852/1492/2093 ms, handoff valid-reply maxima 786 ms disjoint and 689 ms overlap, formal corpus 2623 s, 63 phases in 7217 s on a quiet host)

- Synchrony: rooted `delta_rt` 5000 ms; operator-declared envelope 4500 ms in
  both the flood and readiness profiles; measured valid-reply maxima under
  live flood 1249/1368/2921/4010 ms and in readiness campaigns 2075/2217/
  2524/2731/4210 ms (the last with replies waiting about 3 s on the shared
  single-in-flight PQ peer lanes beside concurrent preparation pushes and an
  ordering commit; not attributed at the retained logging level).
- Reachability: every correct member must be reachable by every relying
  executor for every operation; a member that misses the interval is not
  correct for that operation and yields a typed abort, never authority.
- Durability and storage: schema-9 authenticated journal with reserved record
  and anchor allocations per domain (rooted lifetime budgets), reserved receipt
  envelopes (tens of MiB per effect, initialized before QUV), reserved endpoint
  records, claim-index files, reserved outbox arenas; policy root v8 commits
  every charge.
- Service: active service budget charged from exclusive admission including
  reserved-storage initialization and the executor's runtime-finality
  critical section; on this host the flood profile is budgeted at 16 s
  (5 s interval, 11 s continuation) after measured release maxima of
  10.25 s, 10.20 s and 13.01 s (the last on a host carrying concurrent
  CPU-heavy work, with an 11 s finality stall inside the operation); the
  readiness profile stays at 10 s (5 s + 5 s) with measured maxima below
  9.6 s. A late release is a declared failure, never progress.
- End-to-end singleton cost: 5.6–6.6 s unflooded, 8.4–11.0 s under terminal
  replay pressure, 7.3–10.3 s under live Byzantine flood on a quiet host and
  up to 13.0 s under concurrent host load; non-starvation fence three
  intervals.
- Cold start: the first operation after a process start is outside the
  envelope (pushes observed 4.7–4.9 s late); operators must warm lanes or treat
  the first typed abort as expected.
- PQ: ML-DSA-44 identities and replies, strict PQ channels only; provisional
  carrier claims bounded (4 per account, 4096 total, 30 s).
- Reconfiguration: live old-root handoff with a QC-certified boundary; disjoint
  and overlapping successor campaigns retained.
- Audit: transcripts are non-authorizing observations.
- Consequence: T10 claim-before-call with reserved storage; reconciliation
  budget from the manifest.

## 6. Fault / property / profile matrix

The exact matrix is `../specs/query_unanimity_fault_property_matrix.md`
(profile table plus the thirteen R1 rows with their R2 dispositions). Its
rows are admitted only as adjudicated by the review named in Section 1.

## 7. No laundering, no amplification

No coordinate of the guarantee vector is raised by composition: PQ v1 ordering
and the QUV effect path stay separate profiles; a QUV audit never raises a
portable-finality coordinate; a rooted policy never raises an assurance beyond
its verified constituents (`GuaranteeMeet` model, M4 no-laundering theorem).

## 8. Admission checklist (all PENDING until filled from retained artifacts)

- [ ] Clean-checkout reproduction of every mandatory gate on the peeled commit
  (retained run directory hashes match the reviewer's run).
- [ ] Fresh independent review disposition `PASS` on the exact commit; every
  `QUV-M17Q-001..013` re-adjudicated; no unresolved critical/high finding.
- [ ] Schemas, code, proofs, receipts, CLI output, documentation, yellow-paper
  wording and public claims agree (verification spec header, policy root v8,
  member schema 9, handoff schema 3, `AFTPQI04/05`, `AFTPQA01`, `AFTCR001`).
- [ ] M12a retained; M12b timing/non-portability boundary explicit.
- [ ] Section 3 separation preserved in every public sentence.
- [ ] Section 5 costs stated wherever the claim is stated.
- [ ] Release notes, immutable tag, manifest, checksums, push commands,
  deployment instructions and publication handoff prepared (Section 9).

## 9. Release artifacts (prepared; owner executes)

Release notes: PENDING (generated from this packet and the retained run once
Section 8 is complete). Manifest and checksums: written by the freeze script
next to the retained run. Owner-only commands, not performed:

```text
git push origin <peeled-commit>:refs/heads/master
git push origin refs/tags/aft-quv-v0-m17q-candidate-r2-2026-09-07
```

Deployment instructions (operator obligations, from the verification spec):
root a per-domain policy (v8) with measured `delta_rt`, envelope, service and
continuation budgets for the target host; provision member custody keys and
external anchor roots on disjoint paths; warm PQ lanes after every process
start; size reserved storage from the rooted charges; retain non-authorizing
audit transcripts; never treat a refusal, timeout, freeze or veto as progress.

Publication handoff: the public statement is the claim of Section 2 with the
boundaries of Sections 2, 4 and 5, nothing more.
